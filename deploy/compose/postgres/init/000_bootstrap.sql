-- Enable useful extensions in dev (safe to keep; idempotent in a fresh cluster)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;
