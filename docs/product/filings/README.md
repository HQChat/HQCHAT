# Regulatory filings — drafts

Two draft letters, one per authority, for the cryptography in hqchat.

| File | Authority | Regime | Status |
|---|---|---|---|
| [`anssi-declaration.md`](anssi-declaration.md) | ANSSI (France) | Déclaration de fourniture d'un moyen de cryptologie | **Draft — unsent** |
| [`bis-ccats-request.md`](bis-ccats-request.md) | BIS (US), copy to NSA | Commodity classification (CCATS) / ECCN 5A002–5D002 | **Draft — unsent** |

Both are drafts to be reviewed before sending, and neither is legal advice. The
technical content is verified against the code and is the part worth trusting;
the regulatory framing is the part to have checked.

Read [`../export-compliance.md`](../export-compliance.md) first: it holds the
cryptography inventory these drafts are written from, and the Xcode setting
(`ITSAppUsesNonExemptEncryption = NO` on iOS) that must be corrected before
anything is sent.

## Before sending either

1. **Have both reviewed by an export-control professional.** The US path in
   particular turns on a judgement this repo is not qualified to make — whether
   HQC counts as a "published standard" today. That single question decides
   between a CCATS request and a one-page self-classification.
2. **Decide what you are actually asking for.** These are *compliance* filings —
   permission to distribute. If what you want instead is for ANSSI or NIST to
   *evaluate* the protocol, that is a different letter to a different desk
   (ANSSI's CSPN scheme, or an academic venue). Say so and it can be drafted.
3. **Fill every `[…]` placeholder.** They are legal identity, dates and contact
   details that must not be guessed.
