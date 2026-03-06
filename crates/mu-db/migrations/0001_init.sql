CREATE TABLE IF NOT EXISTS accounts (
    id            BIGSERIAL    PRIMARY KEY,
    username      VARCHAR(10)  NOT NULL UNIQUE,
    password_hash TEXT         NOT NULL,
    is_banned     BOOLEAN      NOT NULL DEFAULT FALSE,
    banned_until  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts (username);


CREATE TABLE IF NOT EXISTS characters (
    id          BIGSERIAL    PRIMARY KEY,
    account_id  BIGINT       NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slot        SMALLINT     NOT NULL CHECK (slot BETWEEN 0 AND 4),
    name        VARCHAR(10)  NOT NULL UNIQUE,
    class       SMALLINT     NOT NULL DEFAULT 0,
    level       SMALLINT     NOT NULL DEFAULT 1 CHECK (level BETWEEN 1 AND 400),
    map_id      SMALLINT     NOT NULL DEFAULT 0,
    pos_x       SMALLINT     NOT NULL DEFAULT 135,
    pos_y       SMALLINT     NOT NULL DEFAULT 127,
    experience  BIGINT       NOT NULL DEFAULT 0,
    hero_state  SMALLINT     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, slot)
);
CREATE INDEX IF NOT EXISTS idx_characters_account_id ON characters (account_id);
