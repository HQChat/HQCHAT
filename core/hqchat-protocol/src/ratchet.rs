//! The KEM double ratchet with prekeys (docs/architecture/e2ee-protocol.md),
//! ported from `double-ratchet.ts` (the key schedule) and `ratchet.ts` (the
//! session).
//!
//! A KEM step differs from a DH step in that the encapsulator chooses the
//! secret, so a stepping header carries the sender's fresh public key and a
//! ciphertext encapsulated to the key the peer last advertised:
//!
//! ```text
//! sender:   (ct, ss) = Encap(peer_rk); (root', ck) = root_step(root, ss)
//!           header = { rk: my_new_rk, kem_ct: ct }
//! receiver: ss = Decap(my_rk_sk, ct);  (root', ck) = root_step(root, ss)
//!           adopt peer_rk = rk, and encapsulate to it on the next step
//! ```
//!
//! HQC rejects implicitly: a forged step decapsulates to a pseudo-random
//! secret without error. So [`open`] computes everything into locals and
//! writes the session only after the caller's AEAD open verifies the key.

use hkdf::Hkdf;
use hqc::{Ciphertext, KeyPair, PublicKey, SecretKey, SharedSecret};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Kem};

/// Most message keys kept for out-of-order delivery, across all chains.
pub const MAX_SKIPPED: usize = 2000;
/// A sending chain steps once it has lived this long and been used.
pub const RATCHET_MIN_STEP_INTERVAL_MS: i64 = 900_000;
/// A sending chain steps after this many messages.
pub const RATCHET_MAX_MESSAGES_PER_CHAIN: u32 = 32;
/// Retired chains remembered for replay rejection. Older replays fail to
/// decapsulate, because our ratchet secret rotates on every step we send.
pub const MAX_SEEN_CHAINS: usize = 64;

/// A 32-byte symmetric key: a root, a chain key or a message key. Wiped on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(…)")
    }
}

/// One direction's chain.
#[derive(Debug, Clone)]
pub struct Chain {
    /// The chain key.
    pub ck: SymmetricKey,
    /// Next index this chain produces or expects.
    pub n: u32,
}

/// A message key kept for a message that has not arrived yet.
#[derive(Debug, Clone)]
pub struct SkippedKey {
    /// [`chain_id`] of the ratchet key whose chain produced it.
    pub chain: [u8; 16],
    /// Its index.
    pub n: u32,
    /// The message key.
    pub key: SymmetricKey,
}

/// What an `init` carries besides the message header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitHeader {
    /// Encapsulated to the responder's identity key.
    pub ct_id: Ciphertext,
    /// Encapsulated to the responder's medium-term prekey.
    pub ct_mt: Ciphertext,
    /// Encapsulated to a one-time prekey, with its id.
    pub one_time: Option<(Ciphertext, u32)>,
    /// The initiator's first ratchet key.
    pub rk: PublicKey,
    /// [`chain_id`] of `rk`, so an init carries the same selector as a msg.
    pub cid: [u8; 16],
}

/// The per-message header; every field is bound as AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// [`chain_id`] of the sender's current ratchet key, on every message, so
    /// `n` is always read against the chain that produced it.
    pub cid: [u8; 16],
    /// On a step: the sender's new ratchet key.
    pub rk: Option<PublicKey>,
    /// On a step: encapsulated to the receiver's previous ratchet key.
    pub kem_ct: Option<Ciphertext>,
    /// Index in the sending chain.
    pub n: u32,
    /// Length of the previous sending chain.
    pub pn: u32,
}

/// A conversation's ratchet state. Serialized by the engine, sealed at rest.
#[derive(Debug, Clone)]
pub struct SessionState {
    /// The root key.
    pub root: SymmetricKey,
    /// My ratchet keypair: peers encapsulate to its public half.
    pub rk: KeyPair,
    /// The peer's advertised ratchet key; `None` until the initiator hears back.
    pub peer_rk: Option<PublicKey>,
    /// The sending chain.
    pub send: Option<Chain>,
    /// The receiving chain.
    pub recv: Option<Chain>,
    /// Length of the previous sending chain (the `pn` field).
    pub prev_send_n: u32,
    /// Keys for messages that have not arrived yet, oldest first.
    pub skipped: Vec<SkippedKey>,
    /// Repeated on every outbound frame until the first successful open, so
    /// a failed or retried first send still reaches a peer that has never
    /// seen the session.
    pub pending_init: Option<InitHeader>,
    /// Chains already stepped into, newest last: a replayed step still
    /// decapsulates, so without this it would re-derive the root.
    pub seen_chains: Vec<[u8; 16]>,
    /// Messages sent on the current sending chain, for the step policy.
    pub sent_on_chain: u32,
    /// When the current sending chain started, in milliseconds.
    pub chain_started_at: i64,
}

/// The peer's published bundle, as claimed from `/prekeys/claim`.
#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    /// The peer's pinned identity key.
    pub identity_pk: PublicKey,
    /// The peer's medium-term prekey.
    pub medium_pk: PublicKey,
    /// One one-time prekey and its id, while the pool lasted.
    pub one_time: Option<(PublicKey, u32)>,
}

/// My prekey secrets, to answer an `init`.
pub trait PrekeySecrets {
    /// My identity secret key.
    fn identity_sk(&self) -> &SecretKey;
    /// My medium-term prekey secret.
    fn medium_sk(&self) -> &SecretKey;
    /// The one-time secret for the id the initiator echoed, if not consumed.
    fn one_time_sk(&self, id: u32) -> Option<&SecretKey>;
}

/// What [`seal`] returns.
#[derive(Debug)]
pub struct Sealed {
    /// The message key: seal the payload with it.
    pub key: SymmetricKey,
    /// The header to frame and bind as AAD.
    pub header: MessageHeader,
    /// Present until the peer answers; see [`SessionState::pending_init`].
    pub init: Option<InitHeader>,
}

/// A new root and the chain key that comes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAndChain {
    /// The next root.
    pub root: SymmetricKey,
    /// The chain key for the stepping direction.
    pub chain: SymmetricKey,
}

/// What walking a chain to a target index yields.
#[derive(Debug)]
pub struct ChainWalk {
    /// Keys for the indexes passed on the way, to keep as skipped.
    pub skipped: Vec<(u32, SymmetricKey)>,
    /// The target's message key.
    pub key: SymmetricKey,
    /// The chain key after the target.
    pub next_ck: SymmetricKey,
    /// The index after the target.
    pub next_n: u32,
}

// ── Key schedule ────────────────────────────────────────────────────────────

fn kdf(ikm: &[u8], info: &str) -> SymmetricKey {
    let mut out = SymmetricKey([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"salt"), ikm)
        .expand(info.as_bytes(), &mut out.0)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// The initial root and the initiator's first sending chain. `ss_id` was
/// encapsulated to the peer's pinned identity key and authenticates them;
/// `ss_mt` and the optional `ss_ot` come from prekeys and give forward
/// secrecy. Without a one-time prekey the session is a different one, not
/// the same with a shorter window.
pub fn init_root(
    ss_id: &SharedSecret,
    ss_mt: &SharedSecret,
    ss_ot: Option<&SharedSecret>,
) -> RootAndChain {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(ss_id.as_bytes());
    ikm.extend_from_slice(ss_mt.as_bytes());
    if let Some(ot) = ss_ot {
        ikm.extend_from_slice(ot.as_bytes());
    }
    RootAndChain {
        root: kdf(&ikm, "hqchat/v2/init/root"),
        chain: kdf(&ikm, "hqchat/v2/init/chain"),
    }
}

/// One asymmetric step: the next root and the chain key for the stepping
/// direction. The new root depends on the old one.
pub fn root_step(root: &SymmetricKey, ss: &SharedSecret) -> RootAndChain {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(&root.0);
    ikm.extend_from_slice(ss.as_bytes());
    RootAndChain {
        root: kdf(&ikm, "hqchat/v2/root"),
        chain: kdf(&ikm, "hqchat/v2/chain"),
    }
}

/// The message key at a chain key.
pub fn message_key(ck: &SymmetricKey) -> SymmetricKey {
    kdf(&ck.0, "hqchat/v2/msg")
}

/// The next chain key.
pub fn chain_next(ck: &SymmetricKey) -> SymmetricKey {
    kdf(&ck.0, "hqchat/v2/ck")
}

/// Walks a receiving chain from `from_n` to `target_n` inclusive. Refuses a
/// gap past [`MAX_SKIPPED`] before doing any work: `target_n` comes from an
/// unauthenticated header.
pub fn walk_chain(ck: &SymmetricKey, from_n: u32, target_n: u32) -> Result<ChainWalk, Error> {
    if target_n < from_n {
        return Err(Error::Invalid("walk_chain: target before start"));
    }
    if (target_n - from_n) as usize > MAX_SKIPPED {
        return Err(Error::Invalid("walk_chain: gap exceeds MAX_SKIPPED"));
    }
    let next_n = target_n
        .checked_add(1)
        .ok_or(Error::Invalid("walk_chain: chain exhausted"))?;
    let mut skipped = Vec::with_capacity((target_n - from_n) as usize);
    let mut cur = ck.clone();
    for n in from_n..target_n {
        skipped.push((n, message_key(&cur)));
        cur = chain_next(&cur);
    }
    Ok(ChainWalk {
        skipped,
        key: message_key(&cur),
        next_ck: chain_next(&cur),
        next_n,
    })
}

/// The 16-byte selector naming a ratchet public key, and so the chain it
/// produced: the first half of its SHA-256.
pub fn chain_id(rk: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(rk);
    digest[..16].try_into().expect("16 of 32 bytes")
}

// ── Session ─────────────────────────────────────────────────────────────────

/// Initiator side: derives the root from the peer's bundle and opens a
/// sending chain, so the first message can be sent while the peer is offline.
pub fn start_as_initiator(
    kem: &dyn Kem,
    bundle: &PrekeyBundle,
    now: i64,
) -> Result<(SessionState, InitHeader), Error> {
    let (ct_id, ss_id) = kem.encapsulate(&bundle.identity_pk)?;
    let (ct_mt, ss_mt) = kem.encapsulate(&bundle.medium_pk)?;
    let one_time = match &bundle.one_time {
        Some((pk, id)) => Some((kem.encapsulate(pk)?, *id)),
        None => None,
    };
    let start = init_root(&ss_id, &ss_mt, one_time.as_ref().map(|((_, ss), _)| ss));
    let mine = kem.generate_keypair()?;
    let header = InitHeader {
        ct_id,
        ct_mt,
        one_time: one_time.map(|((ct, _), id)| (ct, id)),
        cid: chain_id(mine.public.as_bytes()),
        rk: mine.public.clone(),
    };
    let state = SessionState {
        root: start.root,
        rk: mine,
        peer_rk: None,
        send: Some(Chain {
            ck: start.chain,
            n: 0,
        }),
        recv: None,
        prev_send_n: 0,
        skipped: Vec::new(),
        pending_init: Some(header.clone()),
        seen_chains: Vec::new(),
        sent_on_chain: 0,
        chain_started_at: now,
    };
    Ok((state, header))
}

/// Responder side: rebuilds the root from an `init` and opens the matching
/// receiving chain. `None` when the one-time secret is gone or the KEM fails;
/// callers keep any existing session then, so a replayed init cannot reset a
/// conversation.
pub fn start_as_responder(
    kem: &dyn Kem,
    secrets: &dyn PrekeySecrets,
    init: &InitHeader,
    now: i64,
) -> Option<SessionState> {
    let ss_id = kem.decapsulate(secrets.identity_sk(), &init.ct_id).ok()?;
    let ss_mt = kem.decapsulate(secrets.medium_sk(), &init.ct_mt).ok()?;
    let ss_ot = match &init.one_time {
        Some((ct, id)) => Some(kem.decapsulate(secrets.one_time_sk(*id)?, ct).ok()?),
        None => None,
    };
    let start = init_root(&ss_id, &ss_mt, ss_ot.as_ref());
    let mine = kem.generate_keypair().ok()?;
    Some(SessionState {
        root: start.root,
        rk: mine,
        peer_rk: Some(init.rk.clone()),
        send: None,
        recv: Some(Chain {
            ck: start.chain,
            n: 0,
        }),
        prev_send_n: 0,
        skipped: Vec::new(),
        pending_init: None,
        seen_chains: vec![chain_id(init.rk.as_bytes())],
        sent_on_chain: 0,
        chain_started_at: now,
    })
}

/// Whether the next send steps: always when there is no sending chain yet,
/// never before the peer has advertised a key or on an unused chain,
/// otherwise once the chain is full or old (the post-compromise window).
pub fn should_step(state: &SessionState, now: i64) -> bool {
    if state.peer_rk.is_none() {
        return false;
    }
    if state.send.is_none() {
        return true;
    }
    if state.sent_on_chain == 0 {
        return false;
    }
    if state.sent_on_chain >= RATCHET_MAX_MESSAGES_PER_CHAIN {
        return true;
    }
    now - state.chain_started_at >= RATCHET_MIN_STEP_INTERVAL_MS
}

/// Takes the next sending key, stepping first when [`should_step`] says so.
/// The header must be bound as the payload's AAD.
pub fn seal(kem: &dyn Kem, state: &mut SessionState, now: i64) -> Result<Sealed, Error> {
    let mut stepped = None;
    if should_step(state, now) {
        let peer_rk = state
            .peer_rk
            .as_ref()
            .expect("should_step requires a peer key");
        let (ct, ss) = kem.encapsulate(peer_rk)?;
        let next = root_step(&state.root, &ss);
        let mine = kem.generate_keypair()?;
        state.root = next.root;
        state.prev_send_n = state.send.as_ref().map_or(0, |c| c.n);
        state.send = Some(Chain {
            ck: next.chain,
            n: 0,
        });
        stepped = Some((mine.public.clone(), ct));
        state.rk = mine;
        state.sent_on_chain = 0;
        state.chain_started_at = now;
    }
    let cid = chain_id(state.rk.public.as_bytes());
    let send = state.send.as_mut().ok_or(Error::Invalid(
        "seal: no sending chain and no peer key to step against",
    ))?;
    let n = send.n;
    send.n = n
        .checked_add(1)
        .ok_or(Error::Invalid("seal: chain exhausted"))?;
    let key = message_key(&send.ck);
    send.ck = chain_next(&send.ck);
    state.sent_on_chain += 1;
    let (rk, kem_ct) = match stepped {
        Some((rk, ct)) => (Some(rk), Some(ct)),
        None => (None, None),
    };
    Ok(Sealed {
        key,
        header: MessageHeader {
            cid,
            rk,
            kem_ct,
            n,
            pn: state.prev_send_n,
        },
        init: state.pending_init.clone(),
    })
}

/// Keys left on a retiring chain: its id and the (index, key) pairs.
type ChainTail = ([u8; 16], Vec<(u32, SymmetricKey)>);

/// A receiving step computed from a header, not yet committed.
struct PendingStep {
    root: SymmetricKey,
    peer_rk: PublicKey,
    recv: Chain,
    entered: [u8; 16],
    /// Keys left on the retiring chain (up to `pn`), cached once committed.
    tail: Option<ChainTail>,
}

/// The step a header asks for into a new chain, or `None` unless it is a
/// well-formed step to an unseen chain whose ciphertext decapsulates.
fn compute_step(
    kem: &dyn Kem,
    state: &SessionState,
    header: &MessageHeader,
    current: Option<[u8; 16]>,
) -> Option<PendingStep> {
    let (rk, kem_ct) = (header.rk.as_ref()?, header.kem_ct.as_ref()?);
    if chain_id(rk.as_bytes()) != header.cid || state.seen_chains.contains(&header.cid) {
        return None;
    }
    let ss = kem.decapsulate(&state.rk.secret, kem_ct).ok()?;

    // `pn` is attacker-chosen and caching evicts, so the tail is only computed here.
    let mut tail = None;
    if let (Some(recv), Some(current)) = (&state.recv, current)
        && header.pn > recv.n
        && (header.pn - recv.n) as usize <= MAX_SKIPPED
    {
        let walked = walk_chain(&recv.ck, recv.n, header.pn - 1).ok()?;
        let mut keys = walked.skipped;
        keys.push((header.pn - 1, walked.key));
        tail = Some((current, keys));
    }
    let next = root_step(&state.root, &ss);
    Some(PendingStep {
        root: next.root,
        peer_rk: rk.clone(),
        recv: Chain {
            ck: next.chain,
            n: 0,
        },
        entered: header.cid,
        tail,
    })
}

fn cache_skipped(state: &mut SessionState, chain: [u8; 16], keys: Vec<(u32, SymmetricKey)>) {
    state.skipped.extend(
        keys.into_iter()
            .map(|(n, key)| SkippedKey { chain, n, key }),
    );
    if state.skipped.len() > MAX_SKIPPED {
        let excess = state.skipped.len() - MAX_SKIPPED;
        state.skipped.drain(..excess);
    }
}

fn remember_chain(state: &mut SessionState, cid: [u8; 16]) {
    state.seen_chains.push(cid);
    if state.seen_chains.len() > MAX_SEEN_CHAINS {
        let excess = state.seen_chains.len() - MAX_SEEN_CHAINS;
        state.seen_chains.drain(..excess);
    }
}

/// The message key for an inbound header, or `None`: a replay, a retired
/// chain, a gap too large, or a payload that does not authenticate (none is
/// an error). `verify` is the AEAD open and the only authenticator; `state`
/// is written only after it returns true.
pub fn open(
    kem: &dyn Kem,
    state: &mut SessionState,
    header: &MessageHeader,
    verify: &mut dyn FnMut(&SymmetricKey) -> bool,
) -> Option<SymmetricKey> {
    // Skipped keys first, so a late message resolves without touching live state.
    if let Some(i) = state
        .skipped
        .iter()
        .position(|s| s.chain == header.cid && s.n == header.n)
    {
        if !verify(&state.skipped[i].key) {
            return None;
        }
        return Some(state.skipped.remove(i).key);
    }

    let current = state.peer_rk.as_ref().map(|rk| chain_id(rk.as_bytes()));
    let step = if Some(header.cid) == current {
        None
    } else {
        Some(compute_step(kem, state, header, current)?)
    };
    let recv = match &step {
        Some(step) => &step.recv,
        None => state.recv.as_ref()?,
    };
    if header.n < recv.n {
        return None;
    }
    let walk = walk_chain(&recv.ck, recv.n, header.n).ok()?;
    if !verify(&walk.key) {
        return None;
    }

    if let Some(step) = step {
        state.root = step.root;
        state.peer_rk = Some(step.peer_rk);
        if let Some((cid, keys)) = step.tail {
            cache_skipped(state, cid, keys);
        }
        remember_chain(state, step.entered);
    }
    cache_skipped(state, header.cid, walk.skipped);
    state.recv = Some(Chain {
        ck: walk.next_ck,
        n: walk.next_n,
    });
    state.pending_init = None;
    Some(walk.key)
}
