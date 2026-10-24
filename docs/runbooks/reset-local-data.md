# Resetting the app's local data

`DataResetService.resetAllData` is the one routine that wipes the app. It runs
every step even when one fails and reports whether all of them succeeded.

## What it removes

| Data | Where |
|---|---|
| Each profile's core store: identity, prekey secrets, contacts, sessions, messages, frames received locked (all sealed by the core) | `Application Support/core/{profileId}/` (`ChatStore.coreRoot()`) |
| Profiles (name, home server, tier) | the SwiftData store |
| Device keys and the core's state secrets | Secure Enclave and Keychain, service `app.hqchat.messagekeys` (both keychains on macOS) |
| Protection-tier markers | Keychain, service `app.hqchat.keyprotection` |
| What a 3.1.1 install left, until `Migration/` is removed | Keychain services `app.hqchat.profile.{profileId}` (and any such item of a profile the store no longer knows), `app.hqchat.aeskeys` and `app.hqchat.aeskeys.v2`; UserDefaults `app.hqchat.currentUsername` and `unsecureKeyHoldEnabled` |

It keeps the accepted terms version (`eula.acceptedVersion`): it belongs to
the person, not to an identity.

## Ways to run it

- **Settings → Account → reset all data on this device.** Local only: server
  accounts are left as they are.

**Settings → Account → delete my account** is not a reset: it deletes the
active profile's account on the server (when signed in), then that profile
alone, through `ProfileManager.deleteProfile` (its core store, its device key
and state secret, its tier marker, its row). Other profiles stay.
- **Profile selection → reset all** (debug builds, shown only when a profile
  exists). The same local reset.
- **`UITEST_FRESH=1`** in the launch environment of a debug build: wipes once
  at launch, for UI tests.

## By hand

Removing the macOS container deletes the core stores, the SwiftData store and
the preferences:

```bash
rm -rf ~/Library/Containers/martin.rougeron.DissQus
```

Keys are another matter: the device keys, state secrets and markers live in
the data protection keychain and the Secure Enclave, which the `security` tool
and Keychain Access cannot reach. Reset from the app, which deletes them all.
Without its key and state secret, a core store left behind is unreadable. On
iOS, deleting the app leaves its Keychain items behind; the next reset from the
app sweeps them by service name.
