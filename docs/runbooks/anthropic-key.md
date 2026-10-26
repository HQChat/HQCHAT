# The helper's Anthropic key

The helper bot answers free text with Claude Haiku for friends who sent
`/ai on` (`services/bot/src/assistant.ts`). The key that pays for it is the
one secret only the bot holds. The repository is public, so the key goes
nowhere a reader of the repository, a CI log or the server process could see
it.

## Where the key lives

| Step | Where | Who can read it |
|---|---|---|
| 1 | The GitHub Environment secret `ANTHROPIC_API_KEY`, one per environment, behind the environment's protection rules. Never a repository-wide secret. | Deploy, for that environment |
| 2 | The app host's secret bundle, sealed with age to the host's post-quantum identity and signed (`infra/scripts/publish-secrets.sh`; the value goes through a file descriptor, never a command line). | The app host |
| 3 | `/etc/hqcat/secrets/anthropic_api_key`, root, `0600` | root |
| 4 | `hqcat-bot`'s systemd credential (`LoadCredential`), only when the environment sets `botAi` (`infra/nixos/modules/app.nix`). `hqcat-server` never loads it. | the bot's process |
| 5 | Read from `ANTHROPIC_API_KEY_PATH` and handed to the SDK. It is not put in the environment, and an `ANTHROPIC_API_KEY` variable stops the bot in production. Logs and Sentry events redact `sk-ant-…` (`services/common/src/scrub.ts`). | the SDK's client |

The bot's npm workspace is the only one with the Anthropic SDK: the server's
package does not contain it.

## Turning AI replies on in an environment

1. In the [Anthropic Console](https://console.anthropic.com), create a
   workspace for this environment only, for example `hqchat-bot-production`.
   Give it a **monthly spend limit** and usage alerts. The spend limit is the
   backstop if everything else fails.
2. Create an API key in that workspace, named after the environment.
3. Store it without it touching your shell history: run
   `gh secret set ANTHROPIC_API_KEY --env <environment>` and paste the key at
   the prompt.
4. In `infra/environments/<environment>.json`, set
   `"botAi": { "dailyLimit": 2000 }`. That is the most AI replies a day, for
   everyone together. Each friend also gets at most 10 a minute and 50 a day.
5. Merge, and Deploy. The bot's log says
   `AI replies on for those who opt in (claude-haiku-5-5, 2000 a day)`.

Do this on a test environment before production, and only after `/privacy`
lists Anthropic and the app shows the helper's AI badge.

Check it:

- `systemctl show hqcat-server -p LoadCredential` does not name
  `anthropic_api_key`; `systemctl show hqcat-bot -p LoadCredential` does.
- `tr '\0' '\n' </proc/$(systemctl show -p MainPID --value hqcat-bot)/environ | grep -c sk-ant`
  prints `0`.
- On a new account: the welcome mentions `/ai on`; free text gets a pointer to
  `/ai`; after `/ai on` the answer comes from Haiku.
- The Console shows the usage under the bot's workspace only.

## Cost

A reply costs at most about 15,000 tokens in (the last 10 exchanges, each
message under 4,000 characters) and 1,024 out, a fraction of a cent at Haiku
prices. The daily limit therefore bounds the bill, however many accounts ask.
To lower it, lower `dailyLimit` and Deploy.

## Rotating the key

1. Create the new key in the same workspace.
2. Run `gh secret set ANTHROPIC_API_KEY --env <environment>` with the new key.
3. Deploy. `publish-secrets.sh` ships the bundle and the bot restarts with
   the new key.
4. Revoke the old key in the Console.

## If the key leaks

1. **Revoke it in the Console first.** The bot sees the refusal, logs
   `the Anthropic key was refused`, and makes no more calls until a restart.
   Users get a fixed "can't answer" line.
2. Look at the workspace's usage for calls that were not the bot's.
3. Rotate as above.

A key committed to this repository is public the moment it is pushed.
Revoking it is the fix; rewriting history is not. The `scan` workflow's
gitleaks step uses gitleaks' default rules, which include Anthropic keys,
and fails if `.gitleaks.toml` stops extending them.

## Turning AI replies off

Set `"botAi": null` and Deploy: the bot no longer gets the key, and answers
as it did before. To stop it at once, revoke the key.
