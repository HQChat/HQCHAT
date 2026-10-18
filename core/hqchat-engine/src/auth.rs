//! Sign-in and credentials (docs/architecture/auth-flow.md): the HQC
//! challenge at `/auth/init`, the proof and a fresh Ed25519 signing key at
//! `/auth/verify`, `/auth/refresh` for a new signing key on the same session,
//! the server clock offset, and the account actions that need a session.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hqchat_protocol::mqtt_proof::{self, SigningKey};
use hqchat_protocol::{OsEntropy, PeerId, auth_proof};
use serde_json::json;

use crate::core::Core;
use crate::effect::{Action, ConnState, Effect, Method, UnlockReason};
use crate::http::{Answer, Pending};
use crate::types::{CoreError, Device, PushToken};

/// A signing key with less than this left is refreshed rather than used.
pub(crate) const KEY_REFRESH_MARGIN_MS: i64 = 120_000;

/// The session and the MQTT credentials, in memory only.
#[derive(Debug, Default)]
pub(crate) struct Auth {
    pub token: Option<String>,
    pub signing: Option<SigningKey>,
    pub key_id: Option<String>,
    /// Expiry of the signing key, on the device clock.
    pub key_expires_at: i64,
    /// Server clock minus device clock, in milliseconds.
    pub clock_offset_ms: i64,
    pub in_flight: bool,
}

impl Auth {
    /// Unix seconds on the server's clock.
    pub fn server_now_sec(&self, now: i64) -> i64 {
        (now + self.clock_offset_ms).div_euclid(1000)
    }

    pub fn fresh(&self, now: i64) -> bool {
        self.token.is_some()
            && self.signing.is_some()
            && self.key_expires_at - now > KEY_REFRESH_MARGIN_MS
    }
}

impl Core {
    /// Signs in when unlocked; otherwise asks for the unlock it needs.
    pub fn ensure_signed_in(&mut self, now: i64) {
        if self.auth.in_flight || self.auth.fresh(now) {
            return;
        }
        if self.auth.token.is_some() && self.auth.signing.is_some() {
            return self.refresh();
        }
        match self.unlocked.as_ref() {
            Some(u) => {
                let pk = hex::encode(u.identity.public.as_bytes());
                self.auth.in_flight = true;
                self.emit(Effect::Connection(ConnState::Authenticating));
                self.request(
                    Method::Post,
                    "/auth/init",
                    Some(json!({ "pk": pk })),
                    false,
                    Pending::AuthInit,
                );
            }
            None => self.emit(Effect::NeedUnlock {
                reason: UnlockReason::SignIn,
            }),
        }
    }

    pub fn on_auth_init(&mut self, a: Answer, now: i64) {
        let Some(ct) = a.str("ct").and_then(|ct| STANDARD.decode(ct).ok()) else {
            return self.auth_failed(&a);
        };
        let Ok(u) = self.unlocked() else {
            self.auth.in_flight = false;
            return self.emit(Effect::NeedUnlock {
                reason: UnlockReason::SignIn,
            });
        };
        let (Ok(ct), pk) = (
            hqc::Ciphertext::from_bytes(&ct),
            hex::encode(u.identity.public.as_bytes()),
        ) else {
            return self.auth_failed(&a);
        };
        let Ok(ss) = hqc::decapsulate(&u.identity.secret, &ct) else {
            return self.auth_failed(&a);
        };
        let Ok(signing) = SigningKey::generate(&mut OsEntropy) else {
            return self.auth_failed(&a);
        };
        let body = json!({
            "pk": pk,
            "solution": STANDARD.encode(auth_proof::auth_proof(&ss)),
            "mqttSigningKey": STANDARD.encode(signing.public_key()),
        });
        let _ = now;
        self.request(
            Method::Post,
            "/auth/verify",
            Some(body),
            false,
            Pending::AuthVerify { signing },
        );
    }

    pub fn on_auth_verify(&mut self, a: Answer, signing: SigningKey, now: i64) {
        let Some(token) = a.str("sessionToken").map(str::to_owned) else {
            return self.auth_failed(&a);
        };
        if self
            .me
            .as_ref()
            .is_none_or(|me| verified_id(&a, me).is_err())
        {
            return self.auth_failed(&a);
        }
        self.auth.token = Some(token);
        self.adopt(&a, signing, now);
    }

    pub fn refresh(&mut self) {
        let Ok(signing) = SigningKey::generate(&mut OsEntropy) else {
            return;
        };
        let body = json!({ "mqttSigningKey": STANDARD.encode(signing.public_key()) });
        self.auth.in_flight = true;
        self.request(
            Method::Post,
            "/auth/refresh",
            Some(body),
            true,
            Pending::AuthRefresh { signing },
        );
    }

    pub fn on_auth_refresh(&mut self, a: Answer, signing: SigningKey, now: i64) {
        if a.status == 401 {
            // The session lapsed: a full sign-in.
            self.auth = crate::auth::Auth {
                clock_offset_ms: self.auth.clock_offset_ms,
                ..Default::default()
            };
            return self.ensure_signed_in(now);
        }
        self.adopt(&a, signing, now);
    }

    /// Takes the signing key the server registered and the server clock.
    fn adopt(&mut self, a: &Answer, signing: SigningKey, now: i64) {
        self.auth.in_flight = false;
        let Some(key_id) = a.str("mqttKeyId").map(str::to_owned) else {
            return self.auth_failed(a);
        };
        if let Some(server_time) = a.body.get("serverTime").and_then(|v| v.as_i64()) {
            self.auth.clock_offset_ms = server_time * 1000 - now;
        }
        let expires = a
            .body
            .get("mqttKeyExpiresAt")
            .and_then(|v| v.as_i64())
            .map_or(now + 12 * 3600 * 1000, |s| {
                s * 1000 - self.auth.clock_offset_ms
            });
        self.auth.signing = Some(signing);
        self.auth.key_id = Some(key_id);
        self.auth.key_expires_at = expires;
        self.on_signed_in(now);
    }

    fn auth_failed(&mut self, a: &Answer) {
        self.auth.in_flight = false;
        self.emit(Effect::Connection(ConnState::Offline));
        self.fail(Action::SignIn, a);
    }

    /// What follows a sign-in or refresh: the directory, the prekeys and
    /// the connection.
    pub fn on_signed_in(&mut self, now: i64) {
        self.sync_directory();
        self.ensure_prekeys(now);
        self.connect(now);
    }

    /// A fresh CONNECT password; `None` without a usable signing key.
    pub fn connect_password(&self, now: i64) -> Option<String> {
        let me = self.me.as_ref()?;
        let (key, key_id) = (self.auth.signing.as_ref()?, self.auth.key_id.as_ref()?);
        mqtt_proof::sign_connect(
            me,
            key_id,
            key,
            self.auth.server_now_sec(now),
            &mut OsEntropy,
        )
        .ok()
    }

    // ── Account actions ────────────────────────────────────────────────────

    pub fn set_username(&mut self, username: &str) {
        self.request(
            Method::Post,
            "/username",
            Some(json!({ "username": username })),
            true,
            Pending::Action(Action::SetUsername),
        );
    }

    pub fn register_push(&mut self, token: &PushToken) {
        let body = match (token, self.config.device) {
            (PushToken::Apns { token, sandbox }, device) => json!({
                "platform": if device == Device::Macos { "macos" } else { "ios" },
                "environment": if *sandbox { "sandbox" } else { "production" },
                "token": token,
            }),
            // The server's push bridge speaks APNs only until phase 4.
            (PushToken::Fcm { token }, _) => {
                json!({ "platform": "android", "environment": "production", "token": token })
            }
            (PushToken::UnifiedPush { endpoint }, _) => {
                json!({ "platform": "unifiedpush", "environment": "production", "token": endpoint })
            }
        };
        self.request(
            Method::Post,
            "/push/token",
            Some(body),
            true,
            Pending::Action(Action::RegisterPush),
        );
    }

    pub fn delete_account(&mut self) {
        self.request(
            Method::Post,
            "/account/delete",
            None,
            true,
            Pending::DeleteAccount,
        );
    }

    /// The server deleted the account: this profile's data goes too.
    pub(crate) fn on_account_deleted(&mut self, a: Answer) {
        if !a.ok() {
            return self.fail(Action::DeleteAccount, &a);
        }
        for key in self.store.list(String::new()) {
            self.store.delete(key);
        }
        self.unlocked = None;
        self.me = None;
        self.peers.clear();
        self.has_identity = false;
        self.auth = Auth::default();
        self.emit(Effect::AccountDeleted);
    }
}

/// The id in a verify answer, checked against our own.
pub(crate) fn verified_id(a: &Answer, me: &PeerId) -> Result<(), CoreError> {
    match a.str("id") {
        Some(id) if id == me.as_str() => Ok(()),
        _ => Err(CoreError::Protocol(
            "the server signed in another id".into(),
        )),
    }
}
