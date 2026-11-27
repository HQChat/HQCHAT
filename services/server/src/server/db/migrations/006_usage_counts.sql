-- How many people use the app, as numbers only. Days are UTC.
--
-- active_today is the one place an account appears: an account that signed in
-- on a day, unlogged, until the rollup turns that day into a count and deletes
-- its rows. Nothing here says who was active on any day before today.

CREATE UNLOGGED TABLE active_today (
  day date NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')::date,
  id  text NOT NULL CHECK (id ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (day, id)
);

CREATE TABLE usage_daily (
  day         date PRIMARY KEY,
  active      integer NOT NULL DEFAULT 0 CHECK (active >= 0),
  peak_online integer NOT NULL DEFAULT 0 CHECK (peak_online >= 0)
);

-- Apple's daily first-time download units, cached so the all-time figure is a sum.
CREATE TABLE app_downloads (
  day   date PRIMARY KEY,
  units integer NOT NULL CHECK (units >= 0)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON active_today, usage_daily, app_downloads TO ${APP_ROLE};
