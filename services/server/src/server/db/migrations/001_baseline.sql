-- HQChat schema. Clients are named by id = sha256(lowercase hex public key),
-- 64 hex characters; the public key itself is stored only in users.identity_pk.
-- ${APP_ROLE} is the role the services connect as (see src/server/db/migrate.ts).

CREATE EXTENSION IF NOT EXISTS citext;

CREATE FUNCTION pk_digest(t text) RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
  AS $$ SELECT sha256(convert_to(t, 'UTF8')) $$;

CREATE TABLE users (
  id          text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
  identity_pk text NOT NULL CHECK (encode(pk_digest(identity_pk), 'hex') = id),
  username    citext UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- One row per friendship; convo_id and handshake_id are the random MQTT topic
-- ids only the two members are given.
CREATE TABLE friendships (
  id_lo        text NOT NULL,
  id_hi        text NOT NULL,
  convo_id     text NOT NULL UNIQUE CHECK (convo_id ~ '^[0-9a-f]{64}$')
               DEFAULT (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  handshake_id text NOT NULL UNIQUE CHECK (handshake_id ~ '^[0-9a-f]{64}$')
               DEFAULT (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id_lo, id_hi),
  CHECK (id_lo COLLATE "C" < id_hi COLLATE "C")
);
CREATE INDEX friendships_id_hi_idx ON friendships (id_hi);

CREATE TABLE invites (
  to_id      text NOT NULL,
  from_id    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (to_id, from_id)
);
CREATE INDEX invites_from_id_idx ON invites (from_id);

CREATE TABLE blocks (
  blocker_id text NOT NULL CHECK (blocker_id ~ '^[0-9a-f]{64}$'),
  blocked_id text NOT NULL CHECK (blocked_id ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id),
  CHECK (blocker_id <> blocked_id)
);
CREATE INDEX blocks_blocked_id_idx ON blocks (blocked_id);

CREATE TABLE prekeys_medium (
  id         text PRIMARY KEY,
  prekey     text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE prekeys_onetime (
  id         text NOT NULL,
  key_id     integer NOT NULL,
  prekey     text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, key_id)
);

CREATE TABLE push_tokens (
  id          text PRIMARY KEY,
  platform    text NOT NULL DEFAULT 'ios' CHECK (platform IN ('ios', 'macos')),
  environment text NOT NULL DEFAULT 'production' CHECK (environment IN ('production', 'sandbox')),
  token       text NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE reports (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id     text CHECK (reporter_id IS NULL OR reporter_id ~ '^[0-9a-f]{64}$'),
  reported_id     text NOT NULL CHECK (reported_id ~ '^[0-9a-f]{64}$'),
  conversation_id text NOT NULL CHECK (conversation_id ~ '^[0-9a-f]{64}$'),
  category        text NOT NULL CHECK (category IN ('spam', 'harassment', 'sexual', 'violence', 'csae', 'other')),
  reporter_note   text CHECK (reporter_note IS NULL OR length(reporter_note) <= 2000),
  message_excerpt text CHECK (message_excerpt IS NULL OR length(message_excerpt) <= 4000),
  message_frame   bytea CHECK (message_frame IS NULL OR length(message_frame) <= 262144),
  message_id      text CHECK (message_id IS NULL OR (octet_length(message_id) BETWEEN 1 AND 128 AND message_id !~ '[[:cntrl:]]')),
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL DEFAULT now() + interval '90 days',
  handled_at      timestamptz,
  disposition     text CHECK (disposition IS NULL OR disposition IN ('no-action', 'warned', 'ejected', 'banned')),
  CHECK (reporter_id IS NULL OR reporter_id <> reported_id)
);
CREATE INDEX reports_open_idx ON reports (created_at) WHERE handled_at IS NULL;
CREATE INDEX reports_reported_id_idx ON reports (reported_id);
CREATE INDEX reports_expires_at_idx ON reports (expires_at);

CREATE TABLE supporters (
  name_key     text PRIMARY KEY,
  display_name text NOT NULL,
  first_seen   date NOT NULL DEFAULT current_date
);

-- Short-lived state: unlogged, swept on expiry.

CREATE UNLOGGED TABLE sessions (
  token_hash text PRIMARY KEY,
  id         text NOT NULL,
  iat        timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_id_idx ON sessions (id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE UNLOGGED TABLE auth_challenges (
  id         text PRIMARY KEY,
  proof      text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX auth_challenges_expires_at_idx ON auth_challenges (expires_at);

CREATE UNLOGGED TABLE mqtt_session_keys (
  id         text NOT NULL,
  key_id     text NOT NULL CHECK (key_id ~ '^[0-9a-f]{32}$'),
  pubkey     bytea NOT NULL CHECK (octet_length(pubkey) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (id, key_id)
);
CREATE INDEX mqtt_session_keys_expires_at_idx ON mqtt_session_keys (expires_at);

CREATE UNLOGGED TABLE mqtt_nonces (
  nonce      text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX mqtt_nonces_expires_at_idx ON mqtt_nonces (expires_at);

CREATE UNLOGGED TABLE rate_counters (
  key            text PRIMARY KEY,
  n              integer NOT NULL DEFAULT 0,
  window_ends_at timestamptz NOT NULL
);
CREATE INDEX rate_counters_window_ends_at_idx ON rate_counters (window_ends_at);

GRANT USAGE ON SCHEMA public TO ${APP_ROLE};
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE};
