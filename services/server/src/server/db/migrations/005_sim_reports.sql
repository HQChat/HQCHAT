-- The sim node's hourly health report (src/sim/report.ts): one row per sim
-- and window, plus the fleet's `all` row. Counts and milliseconds only: no
-- message text, no peer ids. The sim connects as ${SIM_ROLE}, which may only
-- add rows and read them back; the app role has no business here.
--
-- The role is created outside migrations (infra/terraform/database.tf), so it
-- may not exist yet when this runs: then nothing is granted here, and the app
-- host's hqcat-sim-grant grants it on a later run once the role exists.

CREATE TABLE sim_reports (
  hour     timestamptz NOT NULL,
  sim      text NOT NULL CHECK (sim ~ '^[A-Za-z0-9_]{1,32}$'),
  metrics  jsonb NOT NULL,
  PRIMARY KEY (hour, sim)
);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${SIM_ROLE}') THEN
    GRANT SELECT, INSERT ON sim_reports TO ${SIM_ROLE};
  END IF;
END
$$;
