CREATE TABLE "kv" (
    "key" TEXT PRIMARY KEY NOT NULL,
    "value" BLOB NOT NULL
);

CREATE TABLE "filter" (
    "filter_name" BLOB PRIMARY KEY NOT NULL,
    "filter_id" BLOB NOT NULL
);
