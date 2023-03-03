use std::{
    borrow::Cow,
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use deadpool_sqlite::{Object as SqliteConn, Pool as SqlitePool, Runtime};
use matrix_sdk_base::{
    media::MediaRequest, store::StoreError as StateStoreError, RoomInfo, StateChanges, StateStore,
};
use matrix_sdk_store_encryption::StoreCipher;
use ruma::{
    events::{
        presence::PresenceEvent,
        receipt::{Receipt, ReceiptThread, ReceiptType},
        AnyGlobalAccountDataEvent, AnyRoomAccountDataEvent, AnySyncStateEvent,
        GlobalAccountDataEventType, RoomAccountDataEventType, StateEventType,
    },
    serde::Raw,
    EventId, OwnedUserId, RoomId, UserId,
};
use rusqlite::OptionalExtension;
use serde::{de::DeserializeOwned, Serialize};
use tokio::fs;
use tracing::{debug, error};

use crate::{
    error::{Error, Result},
    get_or_create_store_cipher,
    utils::{Key, SqliteObjectExt},
    OpenStoreError, SqliteObjectStoreExt,
};

/// A sqlite based cryptostore.
#[derive(Clone)]
pub struct SqliteStateStore {
    store_cipher: Option<Arc<StoreCipher>>,
    path: Option<PathBuf>,
    pool: SqlitePool,
}

impl fmt::Debug for SqliteStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            f.debug_struct("SqliteStateStore").field("path", &path).finish()
        } else {
            f.debug_struct("SqliteStateStore").field("path", &"memory store").finish()
        }
    }
}

impl SqliteStateStore {
    /// Open the sqlite-based crypto store at the given path using the given
    /// passphrase to encrypt private data.
    pub async fn open(
        path: impl AsRef<Path>,
        passphrase: Option<&str>,
    ) -> Result<Self, OpenStoreError> {
        let path = path.as_ref();
        fs::create_dir_all(path).await.map_err(OpenStoreError::CreateDir)?;
        let cfg = deadpool_sqlite::Config::new(path.join("matrix-sdk-crypto.sqlite3"));
        let pool = cfg.create_pool(Runtime::Tokio1)?;

        Self::open_with_pool(pool, passphrase).await
    }

    /// Create a sqlite-based crypto store using the given sqlite database pool.
    /// The given passphrase will be used to encrypt private data.
    pub async fn open_with_pool(
        pool: SqlitePool,
        passphrase: Option<&str>,
    ) -> Result<Self, OpenStoreError> {
        let conn = pool.get().await?;
        run_migrations(&conn).await.map_err(OpenStoreError::Migration)?;
        let store_cipher = match passphrase {
            Some(p) => Some(Arc::new(get_or_create_store_cipher(p, &conn).await?)),
            None => None,
        };

        Ok(Self { store_cipher, path: None, pool })
    }

    fn encode_value(&self, value: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(key) = &self.store_cipher {
            let encrypted = key.encrypt_value_data(value)?;
            Ok(rmp_serde::to_vec_named(&encrypted)?)
        } else {
            Ok(value)
        }
    }

    fn serialize_value(&self, value: &impl Serialize) -> Result<Vec<u8>> {
        let serialized = rmp_serde::to_vec_named(value)?;
        self.encode_value(serialized)
    }

    fn decode_value<'a>(&self, value: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        if let Some(key) = &self.store_cipher {
            let encrypted = rmp_serde::from_slice(value)?;
            let decrypted = key.decrypt_value_data(encrypted)?;
            Ok(Cow::Owned(decrypted))
        } else {
            Ok(Cow::Borrowed(value))
        }
    }

    fn deserialize_value<T: DeserializeOwned>(&self, value: &[u8]) -> Result<T> {
        let decoded = self.decode_value(value)?;
        Ok(rmp_serde::from_slice(&decoded)?)
    }

    fn encode_key(&self, table_name: &str, key: impl AsRef<[u8]>) -> Key {
        let bytes = key.as_ref();
        if let Some(store_cipher) = &self.store_cipher {
            Key::Hashed(store_cipher.hash_key(table_name, bytes))
        } else {
            Key::Plain(bytes.to_owned())
        }
    }

    async fn acquire(&self) -> Result<deadpool_sqlite::Object> {
        Ok(self.pool.get().await?)
    }
}

const DATABASE_VERSION: u8 = 1;

async fn run_migrations(conn: &SqliteConn) -> rusqlite::Result<()> {
    let kv_exists = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'kv'",
            (),
            |row| row.get::<_, u32>(0),
        )
        .await?
        > 0;

    let version = if kv_exists {
        match conn.get_kv("version").await?.as_deref() {
            Some([v]) => *v,
            Some(_) => {
                error!("version database field has multiple bytes");
                return Ok(());
            }
            None => {
                error!("version database field is missing");
                return Ok(());
            }
        }
    } else {
        0
    };

    if version == 0 {
        debug!("Creating database");
    } else if version < DATABASE_VERSION {
        debug!(version, new_version = DATABASE_VERSION, "Upgrading database");
    }

    if version < 1 {
        // First turn on WAL mode, this can't be done in the transaction, it fails with
        // the error message: "cannot change into wal mode from within a transaction".
        conn.execute_batch("PRAGMA journal_mode = wal;").await?;
        conn.with_transaction(|txn| {
            txn.execute_batch(include_str!("../migrations/state_store/001_init.sql"))
        })
        .await?;
    }

    conn.set_kv("version", vec![DATABASE_VERSION]).await?;

    Ok(())
}

#[async_trait]
trait SqliteObjectStateStoreExt: SqliteObjectExt {
    async fn set_filter(&self, filter_name: Key, filter_id: Vec<u8>) -> Result<()> {
        self.execute(
            "INSERT INTO filter (filter_name, filter_id)
             VALUES(?1, ?2)
             ON CONFLICT (filter_name) DO UPDATE SET filter_id = ?2",
            (filter_name, filter_id),
        )
        .await?;
        Ok(())
    }

    async fn get_filter(&self, filter_name: Key) -> Result<Option<Vec<u8>>> {
        Ok(self
            .query_row(
                "SELECT filter_id FROM filter WHERE filter_name = ?",
                (filter_name,),
                |row| row.get(0),
            )
            .await
            .optional()?)
    }
}

#[async_trait]
impl SqliteObjectStateStoreExt for deadpool_sqlite::Object {}

#[async_trait]
impl StateStore for SqliteStateStore {
    type Error = Error;

    async fn save_filter(&self, filter_name: &str, filter_id: &str) -> Result<()> {
        todo!()
    }

    async fn save_changes(&self, changes: &StateChanges) -> Result<()> {
        let changes = changes.to_owned();
        let this = self.clone();
        self.acquire()
            .await?
            .with_transaction(move |txn| {
                // changes.members
                // changes.profiles
                // changes.display_names
                // changes.stripped_members
                // changes.stripped_state
                for (room_id, room_info) in changes.room_infos {}
                // ...
                Ok::<_, Error>(())
            })
            .await?;

        Ok(())
    }

    async fn get_filter(&self, filter_name: &str) -> Result<Option<String>> {
        let filter_name = self.encode_key("filter", filter_name);
        self.acquire()
            .await?
            .get_filter(filter_name)
            .await?
            .map(|value| self.deserialize_value(&value))
            .transpose()
    }

    async fn get_sync_token(&self) -> Result<Option<String>> {
        todo!()
    }

    async fn get_presence_event(&self, user_id: &UserId) -> Result<Option<Raw<PresenceEvent>>> {
        todo!()
    }

    async fn get_state_event(
        &self,
        room_id: &RoomId,
        event_type: StateEventType,
        state_key: &str,
    ) -> Result<Option<Raw<AnySyncStateEvent>>> {
        todo!()
    }

    async fn get_state_events(
        &self,
        room_id: &RoomId,
        event_type: StateEventType,
    ) -> Result<Vec<Raw<AnySyncStateEvent>>> {
        todo!()
    }

    async fn get_profile(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
    ) -> Result<Option<matrix_sdk_base::MinimalRoomMemberEvent>> {
        todo!()
    }

    async fn get_member_event(
        &self,
        room_id: &RoomId,
        state_key: &UserId,
    ) -> Result<Option<matrix_sdk_base::deserialized_responses::RawMemberEvent>> {
        todo!()
    }

    async fn get_user_ids(&self, room_id: &RoomId) -> Result<Vec<OwnedUserId>> {
        todo!()
    }

    async fn get_invited_user_ids(&self, room_id: &RoomId) -> Result<Vec<OwnedUserId>> {
        todo!()
    }

    async fn get_joined_user_ids(&self, room_id: &RoomId) -> Result<Vec<OwnedUserId>> {
        todo!()
    }

    async fn get_room_infos(&self) -> Result<Vec<RoomInfo>> {
        todo!()
    }

    async fn get_stripped_room_infos(&self) -> Result<Vec<RoomInfo>> {
        todo!()
    }

    async fn get_users_with_display_name(
        &self,
        room_id: &RoomId,
        display_name: &str,
    ) -> Result<BTreeSet<OwnedUserId>> {
        todo!()
    }

    async fn get_account_data_event(
        &self,
        event_type: GlobalAccountDataEventType,
    ) -> Result<Option<Raw<AnyGlobalAccountDataEvent>>> {
        todo!()
    }

    async fn get_room_account_data_event(
        &self,
        room_id: &RoomId,
        event_type: RoomAccountDataEventType,
    ) -> Result<Option<Raw<AnyRoomAccountDataEvent>>> {
        todo!()
    }

    async fn get_user_room_receipt_event(
        &self,
        room_id: &RoomId,
        receipt_type: ReceiptType,
        thread: ReceiptThread,
        user_id: &UserId,
    ) -> Result<Option<(ruma::OwnedEventId, Receipt)>> {
        todo!()
    }

    async fn get_event_room_receipt_events(
        &self,
        room_id: &RoomId,
        receipt_type: ReceiptType,
        thread: ReceiptThread,
        event_id: &EventId,
    ) -> Result<Vec<(OwnedUserId, Receipt)>> {
        todo!()
    }

    async fn get_custom_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        todo!()
    }

    async fn set_custom_value(&self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        todo!()
    }

    async fn add_media_content(&self, request: &MediaRequest, content: Vec<u8>) -> Result<()> {
        todo!()
    }

    async fn get_media_content(&self, request: &MediaRequest) -> Result<Option<Vec<u8>>> {
        todo!()
    }

    async fn remove_media_content(&self, request: &MediaRequest) -> Result<()> {
        todo!()
    }

    async fn remove_media_content_for_uri(&self, uri: &ruma::MxcUri) -> Result<()> {
        todo!()
    }

    async fn remove_room(&self, room_id: &RoomId) -> Result<()> {
        todo!()
    }
}
