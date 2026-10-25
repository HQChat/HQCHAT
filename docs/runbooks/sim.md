# Sim node

A production host, `hqchat-<env>-sim`, that runs synthetic users against the
live service and writes down every hour how it went: whether messages arrived,
how many were lost, how long they took, and how much of the hour each account
was connected. It is the one measurement of the service the way a phone sees
it, through the public front door, rather than from inside the VPC.

## What it does

One process, `hqcat-sim` (`services/server/src/sim/`), runs ten accounts,
`echo_01` … `echo_10`, each an ordinary account on the Rust core:

- **Befriends the other sims.** Every hour a few invites go out between sims,
  and now and then a friendship is dropped, so invites, accepts and removals
  keep happening.
- **Accepts half its invites.** Each invite, from a sim or a real user, is
  answered after ten seconds to ten minutes with a coin flip; a declined sim is
  invited again an hour later.
- **Echoes every message exactly.** Whatever a friend sends comes back
  unchanged, real users included (at most 20 echoes a minute to one peer, so
  another echo bot cannot loop with it). The helper bot is never echoed. Real
  users' text is held only long enough to send it back: never logged, stored or
  reported.
- **Pings and times the echo.** Each sim pings a friend every 30 s to 5 min. A
  ping without its echo after 30 s counts as late, after 5 min as lost.
- **Goes away now and then.** A sim drops its network for one to ten minutes,
  so messages to it wait in the broker's offline queue, which is measured too.
- **Uses both transports.** Odd sims (`echo_01`, `echo_03`, …) reach the
  broker over hqn/1, even ones over WebSocket, so the report compares the two.

At the top of every UTC hour each sim's hour becomes one row of
`sim_reports(hour, sim, metrics jsonb)`, and the fleet's sums become a row with
`sim = 'all'`. `hour` is the start of the window the row covers. `metrics`:

| Key | |
|---|---|
| `windowMs` | Length of the window |
| `counts` | Counters: `pingsSent`, `lost`, `late`, `lateAfterLost`, `duplicates`, `corrupted`, `connects`, `drops`, `aways`, `dials.hqn` / `dials.wss`, `sent.<kind>`, `delivery.<kind>.<state>`, `accepted.<who>`, `declined.<who>`, `invitesSent.sims` / `.real`, `echoesBack`, `echoesCapped`, `realUsers`, `failed.<action>.<status>`, … |
| `ms` | Latency percentiles `{n, p50, p95, p99, max}` by bucket: `rtt.hqn.online`, `rtt.wss.offline`, `connect.<from>`, `<state>.<kind>`, … |
| `uptimePct` | Share of the window connected, leaving out the time the sim chose to be away; null when it was away throughout |

A row the database refused waits for the next hour (about a day's worth). The
sim may only add rows and read them back, so a row once written stays as it
was.

## Where it runs

| | |
|---|---|
| Droplet | `sizes.sim` in the environment file (`s-1vcpu-1gb` in production); only an environment that sizes it has one |
| Inbound | SSH only, as the app host's (`adminSshSources`, rate-limited, keys only); no service port |
| Outbound | HTTPS (to `https://<apiHost>` through Cloudflare, WSS at `/mqtt` there, hqn/1 to the broker's public address the server offers), DNS, NTP, and its database pool in the VPC; nothing else, and nothing else in the VPC. It is not on the WireGuard link |
| Database | Its own transaction pool, `hqchat_sim`, as `hqcat_sim`, with TLS verified against the cluster CA. That role may `SELECT` and `INSERT` on `sim_reports` and nothing else (`005_sim_reports.sql`; the app host's `hqcat-db-migrate` repeats the grant on every run) |
| Unit | `hqcat-sim` (`infra/nixos/modules/sim.nix`), in the same sandbox as the server's units, with state in `/var/lib/hqcat-sim` (each sim's core state, and the real users who declined) |
| Secrets | The `sim` bundle: `sim_seeds`, `database_url_sim`, `pg_ca_cert`, `bot_id`. The unit does not start without them |

`sim_seeds` holds one 32-byte hex seed per line, one per account: the seeds
*are* the accounts. They come from the `SIM_SEEDS` secret on the GitHub
Environment, reach the host only in its sealed bundle and never enter the Nix
store. Changing one replaces that account with a new one whose handle is
already taken, so leave them alone.

All ten accounts share the node's one public address, so they share whatever
per-address limits apply to it (nginx on `/mqtt`, the hqn/1 gateway's new
connections a minute, the server's).

## Adding it to an environment

1. Add `"sim": "<droplet size>"` to `sizes` in `infra/environments/<env>.json`.
2. Run `infra/scripts/init-environment.sh <env>` (with the tokens it asks for,
   [deploy runbook](deploy.md#a-new-environment)). On an existing environment
   it only adds what is missing: `SIM_SEEDS` (ten seeds) and
   `AGE_IDENTITY_SIM`. Do this before deploying: the new droplet gets its age
   identity in user data, once, at creation.
3. Run Deploy. Terraform creates the droplet, its firewall, the `hqcat_sim`
   login and its pool, and admits the sim tag to the database firewall; the
   `sim` bundle is published with the others, and `channels/<env>/sim` moves
   with the app and broker channels.

## Reading the report

`scripts/dashboards.sh` (an operator script kept out of git, in the operator's
checkout) opens pgweb on the app database through an SSH tunnel to the app
host, read-only:

```bash
scripts/dashboards.sh <app host ip>
```

Then open `http://127.0.0.1:8081` and query `sim_reports`. The fleet over the
last day:

```sql
SELECT hour,
       (metrics->'counts'->>'pingsSent')::int            AS sent,
       coalesce((metrics->'counts'->>'lost')::int, 0)    AS lost,
       coalesce((metrics->'counts'->>'late')::int, 0)    AS late,
       (metrics->'ms'->'rtt.hqn.online'->>'p95')::int    AS hqn_p95_ms,
       (metrics->'ms'->'rtt.wss.online'->>'p95')::int    AS wss_p95_ms,
       (metrics->>'uptimePct')::numeric                  AS uptime_pct
FROM sim_reports
WHERE sim = 'all' AND hour > now() - interval '24 hours'
ORDER BY hour DESC;
```

Loss by sim over a week, worst first:

```sql
SELECT sim,
       sum(coalesce((metrics->'counts'->>'pingsSent')::int, 0)) AS sent,
       sum(coalesce((metrics->'counts'->>'lost')::int, 0))      AS lost,
       round(100.0 * sum(coalesce((metrics->'counts'->>'lost')::int, 0))
             / nullif(sum(coalesce((metrics->'counts'->>'pingsSent')::int, 0)), 0), 2) AS lost_pct
FROM sim_reports
WHERE sim <> 'all' AND hour > now() - interval '7 days'
GROUP BY sim
ORDER BY lost_pct DESC NULLS LAST;
```

Every counter of the latest hour, and every latency bucket's p99:

```sql
SELECT key, value::int
FROM sim_reports, jsonb_each_text(metrics->'counts')
WHERE sim = 'all' AND hour = (SELECT max(hour) FROM sim_reports)
ORDER BY key;

SELECT key AS bucket, (value->>'n')::int AS n, (value->>'p99')::int AS p99_ms
FROM sim_reports, jsonb_each(metrics->'ms')
WHERE sim = 'all' AND hour = (SELECT max(hour) FROM sim_reports)
ORDER BY p99_ms DESC;
```

Hours with no report (the node, its database pool or the database was down):

```sql
SELECT h AS missing
FROM generate_series(date_trunc('hour', now()) - interval '48 hours',
                     date_trunc('hour', now()) - interval '1 hour',
                     interval '1 hour') AS h
WHERE NOT EXISTS (SELECT 1 FROM sim_reports WHERE sim = 'all' AND hour = h);
```

## Operating it

The host's address and SSH host key are in the Terraform output `hosts`
(sensitive: `terraform output -json hosts`). `ssh root@<sim ip>`, from an
address `adminSshSources` admits.

| To | |
|---|---|
| See it | `systemctl status hqcat-sim`, `journalctl -u hqcat-sim` |
| Restart it | `systemctl restart hqcat-sim` |
| Pause it | `systemctl stop hqcat-sim`. It starts again on the next release, reboot, or change to its bundle; `systemctl mask --runtime hqcat-sim` holds it until a reboot |
| Redeploy it | Run Deploy. The node follows `channels/<env>/sim` like the other hosts; if its `hqcat-health-check` (is `hqcat-sim` active) fails after a switch, the host rolls back and skips that release |
| Remove it | Delete `sizes.sim` from the environment file and run Deploy with `allow_replace`: deleting the droplet, its firewall and the `hqcat_sim` login are protected deletes (`infra/scripts/tf-guard.sh`). `sim_reports` and its rows stay |

Useful units on the node: `hqcat-sim`, `hqcat-host-agent`,
`hqcat-secrets-sync`, `hqcat-netconf`.
