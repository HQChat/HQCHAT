# ANSSI — déclaration de fourniture d'un moyen de cryptologie

> **DRAFT — UNSENT.** Not legal advice. The cryptographic description below is
> verified against the code and is accurate as of 2026-09-01; the regulatory
> framing needs review. France operates a *déclaration* regime for supplying
> means of cryptology providing confidentiality, and a separate *autorisation*
> regime for export outside the EU — confirm which applies, and submit through
> ANSSI's current channel rather than by post if that is what they now use.
>
> Placeholders in `[…]` are legal identity and contact details. Do not guess them.

---

**Objet : déclaration de fourniture d'un moyen de cryptologie — messagerie
chiffrée de bout en bout « hqchat »**

Agence nationale de la sécurité des systèmes d'information
Bureau [service compétent — à confirmer]
51 boulevard de La Tour-Maubourg
75700 Paris 07 SP

[Lieu], le [date]

Madame, Monsieur,

Je vous adresse la présente déclaration au titre de la fourniture d'un moyen de
cryptologie assurant une fonction de confidentialité.

## 1. Déclarant

- Nom et prénom : [nom légal complet]
- Statut : personne physique / [structure juridique le cas échéant]
- Adresse : [adresse postale]
- Courriel : [adresse de contact]
- SIRET, le cas échéant : [SIRET]

Le moyen est développé et fourni à titre individuel. Il n'existe pas de personne
morale distincte à ce jour.

## 2. Identification du moyen

- Dénomination : **hqchat** (publié sur l'App Store sous le nom « HQChat »)
- Nature : application de messagerie instantanée chiffrée de bout en bout, pour
  iOS et macOS, accompagnée d'un service serveur
- Fonction cryptologique : **confidentialité** des communications entre
  utilisateurs (et non uniquement authentification ou contrôle d'intégrité)
- Diffusion envisagée : gratuite, sans contrepartie financière ; le projet est
  financé par des dons volontaires qui n'ouvrent droit à aucune fonctionnalité
- Code source du serveur, de l'infrastructure et des applications : **publié**
  à l'adresse <https://github.com/HQChat/HQCHAT> (serveur et infrastructure sous licence AGPL-3.0)

## 3. Description des fonctions cryptologiques

Le moyen met en œuvre un chiffrement de bout en bout : le serveur relaie des
messages qu'il ne peut pas déchiffrer. Les clés privées sont générées sur
l'appareil de l'utilisateur et n'en sortent jamais.

| Fonction | Algorithme | Paramètres |
|---|---|---|
| Établissement de clé de bout en bout (post-quantique) | **HQC-256** (KEM) | clé publique 7 237 o, clé privée 7 333 o, chiffré 14 421 o, secret partagé 32 o |
| Chiffrement des messages | **AES-256-GCM** | clé 256 bits, nonce 96 bits, tag 128 bits |
| Dérivation de clés | **HKDF-SHA-256** | sorties 32 o, séparation de domaine par étiquette |
| Canal de transport optionnel vers le serveur | **Noise** : **X25519** + HQC-256, **ChaCha20-Poly1305**, SHA-256 | clés 256 bits |
| Authentification de chaque connexion de messagerie | signatures **Ed25519** | clé de session, partie publique enregistrée auprès du serveur |
| Messages conservés sur l'appareil | **ECIES sur P-256** (Secure Enclave d'Apple) protégeant des clés AES-256-GCM | P-256 |
| Empreintes et identifiants | **SHA-256** | — |
| Transport | **TLS** | fourni par le système d'exploitation, nginx et Cloudflare |

**Authentification.** La connexion repose sur un défi-réponse fondé sur le KEM
(le serveur encapsule vers la clé publique annoncée ; le client prouve qu'il
détient la clé privée en renvoyant `HKDF(secret_partagé, "auth")`). Chaque
connexion de messagerie est ensuite authentifiée par une signature Ed25519
d'une clé de courte durée. Les signatures authentifient ; elles ne protègent
jamais le contenu.

### Points appelant votre attention

1. **L'accord de clé de bout en bout n'est pas hybride.** Il repose sur HQC-256
   seul, sans X25519 ni ML-KEM en complément : une faiblesse de HQC ne
   laisserait pas d'algorithme classique pour protéger la confidentialité des
   messages. Cette limite est documentée publiquement. Seul le canal de
   transport optionnel vers le serveur est hybride (X25519 + HQC-256).

2. **Renouvellement de clé (« ratchet ») fondé sur le KEM.** Après un échange
   initial de type PQXDH (clé d'identité, clé intermédiaire à durée de vie de
   7 jours, clé à usage unique), une chaîne racine est réencapsulée lors d'un
   changement de sens de la conversation, dès que la chaîne courante a porté
   32 messages ou vécu 15 minutes, et une chaîne symétrique dérive une clé par
   message. Le destinataire vérifie l'identité de l'initiateur par un défi HQC
   distinct avant d'accepter une session.

3. **Implémentation.** HQC provient de l'implémentation de référence officielle
   (<https://gitlab.com/pqc-hqc/hqc>), compilée sans modification
   algorithmique ; le commit exact est figé dans le dépôt
   (`native/hqc/HQC_UPSTREAM.txt`, actuellement `3a0f86f`). AES-GCM,
   ChaCha20-Poly1305, X25519, Ed25519, P-256, HKDF, HMAC et SHA-256 proviennent
   des bibliothèques Rust publiées RustCrypto et dalek, liées dans le cœur Rust
   commun aux applications et au serveur ; l'ECDH P-256 de la clé matérielle
   est faite par la Secure Enclave (framework Security), et TLS reste celui de
   la plateforme. **Aucun algorithme n'a été conçu par nos soins** ; seul leur
   assemblage protocolaire est propre au projet.

4. **Statut de normalisation de HQC.** HQC a été retenu par le NIST comme
   cinquième algorithme post-quantique ; la norme FIPS correspondante n'était
   pas publiée à la date de rédaction. Le moyen n'utilise donc pas exclusivement
   des algorithmes normalisés au sens strict.

## 4. Documentation jointe

- Spécification du protocole de bout en bout : `docs/architecture/e2ee-protocol.md`
- Modèle de menace, limites et faiblesses assumées : joint séparément
- Inventaire cryptographique : `docs/product/export-compliance.md`
- Code source : <https://github.com/HQChat/HQCHAT>

Je me tiens à votre disposition pour toute précision, pour la fourniture du code
des composants clients, ou pour un échange technique si vous le jugez utile.

Je vous prie d'agréer, Madame, Monsieur, l'expression de ma considération
distinguée.

[Nom]
[Signature]
