# Usage counts

How many people use the app, as numbers only. On the app host:

```
hqcat-ops usage
```

| Line | Source |
|---|---|
| online now | EMQX's client list: account client ids connected right now |
| active today | accounts that signed in (`/auth/verify`, `/auth/refresh`) since 00:00 UTC |
| peak online today | the highest online count, sampled every minute by the server |
| active / peak, last 7 days | `usage_daily`, one row per finished day |
| accounts | `users`, with those created today |
| App Store downloads | first-time downloads from App Store Connect, the latest published day and the sum since `start` |

The helper bot (`BOT_ID`) and the sim accounts (`SIM_PREFIX` + digits, `echo_01`…)
are never counted. Days are UTC; Apple's reports are Pacific days and come out
the next day, so the latest download figure is for yesterday at best.

## What is stored

- `active_today`: the ids that signed in today, unlogged. The server's sweep
  (every 5 minutes) turns each finished day into a count in `usage_daily` and
  deletes its rows, so no table says who was active on a past day. A row is
  also deleted with its account.
- `usage_daily`: per day, the active count and the online peak. Counts only.
- `app_downloads`: per day, Apple's first-time download units.

The privacy page's "what we store" says this; keep the two in step.

## Downloads: setting up the key

1. In App Store Connect → Users and Access → Integrations → Team Keys, create a
   key with the **Sales** role only. Do not reuse the CI key (`ASC_KEY_*`): it
   has the Admin role and must not sit on the app host.
2. Note the key id, the issuer id, and the vendor number (Payments and Financial
   Reports, top left).
3. Add to the environment JSON (`infra/environments/<env>.json`):

   ```json
   "appStoreSales": { "keyId": "…", "issuerId": "…", "vendorNumber": "…", "start": "2026-10-01" }
   ```

   `start` is the first day to count: the launch.
4. Store the private key on the GitHub Environment and deploy:

   ```
   gh secret set ASC_SALES_KEY_P8 --env <environment> < AuthKey_XXXX.p8
   ```

The key reaches the `hqcat-ops` unit only, not the server. The first run
fetches up to 365 days; a longer history fills in on the next runs. A day Apple
has no report for is stored as 0 once it is two days old.
