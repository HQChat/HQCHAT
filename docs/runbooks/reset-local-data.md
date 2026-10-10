# Resetting the app's local data

`DataResetService.resetAllData` is the one routine that wipes the app. It runs
every step even when one fails and reports whether all of them succeeded.

## What it removes

| Data | Where |
|---|---|
| Profiles, contacts, messages | the SwiftData store |
| Identity keys | Keychain, service `app.hqchat.profile.{profileId}` (and any such item of a profile the store no longer knows) |
| Ratchet sessions and prekey secrets | Keychain, service `app.hqchat.aeskeys` |
| At-rest message key pairs and their items | Secure Enclave and Keychain, service `app.hqchat.messagekeys` |
| Protection-tier markers | Keychain, service `app.hqchat.keyprotection` |
| The username awaiting its claim | UserDefaults `app.hqchat.currentUsername` |

It keeps the accepted terms version (`eula.acceptedVersion`) and the fast-unlock
preference (`unsecureKeyHoldEnabled`): they belong to the person, not to an
identity.

## Ways to run it

- **Settings → Account → reset all data on this device.** Local only: server
  accounts are left as they are.

**Settings → Account → delete my account** is not a reset: it deletes the
active profile's account on the server (when signed in), then that profile
alone, through `ProfileManager.deleteProfile` (identity key, tier marker,
message key pair, ratchet sessions, prekey secrets, rows). Other profiles stay.
- **Profile selection → reset all** (debug builds, shown only when a profile
  exists). The same local reset.
- **`UITEST_FRESH=1`** in the launch environment of a debug build: wipes once
  at launch, for UI tests.

## By hand

Removing the macOS container deletes the store and preferences:

```bash
rm -rf ~/Library/Containers/martin.rougeron.DissQus
```

Keys are another matter: the message keys and markers live in the data
protection keychain and the Secure Enclave, which the `security` tool and
Keychain Access cannot reach. Reset from the app, which deletes them all. On
iOS, deleting the app leaves its Keychain items behind; the next reset from the
app sweeps them by service name.
