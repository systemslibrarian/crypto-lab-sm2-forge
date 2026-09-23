# BUILD BRIEF — crypto-lab-sm2-forge

Binding spec: `./CRYPTO-LAB-TEMPLATE.md` (a local, gitignored copy of
`audits/_MASTER-TEMPLATE.md`). Catalog root `CLAUDE.md` wins where they touch.
Lifecycle: Build → Teach → Look → Accessibility → README → Deploy.

## KEY FACTS PINNED (verify each before it enters shipped copy)

- SM2's signature hashes an identity-and-curve prefix Z_A into the message
  BEFORE signing. Z_A = H256(ENTL_A || ID_A || a || b || Gx || Gy || xA || yA).
  This is the single feature that separates SM2 signing from ECDSA — build the
  exhibit around it, not around "another curve signature."
- The default signing identity when none is supplied is the ASCII string
  1234567812345678 (RFC 8998 §3.2.1, citing GM/T 0009-2012). Confirm in RFC 8998.
- SM2 ciphertext has two byte orders in the wild: C1 || C3 || C2 (the GB/T
  32918.4-2016 / SM-standard order) and the older C1 || C2 || C3 (early draft).
  Same math, different serialization — a real interop break. Do not label either
  order "wrong"; label them by their source.
- SM2 uses its own recommended 256-bit prime-field curve (GM/T 0003 / GB/T
  32918.5 Annex), NOT a NIST P-curve. Read its parameters out of the standard;
  do not paste them from memory. Cross-check the base point with @noble/curves.

## NEW DEMO BRIEF

repo name      : crypto-lab-sm2-forge
short name (H1): SM2 Forge
subtitle       : GB/T 32918 · GM/T 0003 · RFC 8998
one-liner      : Sign and encrypt with China's SM2 public-key standard — the ID
                 hashed into every signature, the two ciphertext byte-orders, and
                 a nonce-reuse key recovery against the real verifier.
concept        : SM2 is not "ECDSA on a Chinese curve." Its signature binds an
                 identity prefix into the message, and its ciphertext ships in two
                 incompatible orders — the parts a migration actually trips over.
primitives/spec: SM2 (GB/T 32918-2016 / GM/T 0003-2012), SM3 (GB/T 32905),
                 the SM2 recommended curve (GM/T 0003.5 / GB/T 32918.5 Annex),
                 RFC 8998 ShangMi TLS 1.3 suites for real-world context.
--accent       : #35d6bb   (assigned centrally — do not change in this repo)
favicon        : 🀄
in scope       : SM2 sign/verify with Z_A; SM2 encrypt/decrypt in BOTH C1C3C2 and
                 C1C2C3 order; nonce-reuse private-key recovery (isolated, marked
                 broken); the SM2 curve built and KAT-checked; RFC 8998 context.
non-goals      : No SM2 key exchange (SM2-2) beyond a labelled mention. No SM4/SM3
                 internals (SM3 is used as the required hash, not dissected here —
                 that is world-hashes). No claim that SM2 is weaker or stronger
                 than ECDSA. No TLS handshake implementation. Not an attack on the
                 curve itself. The nonce-reuse path is never the default.

## §1.1 SCOPE

Three panes, left to right, each gated on the one before.

1. THE CURVE — build the SM2 recommended curve from the standard's parameters,
   run a full sign/verify and encrypt/decrypt against the GM/T 0003 Annex
   vectors. Purpose: prove standard-compliance before the exhibit dissects it.
2. THE SIGNATURE — the headline. Show Z_A being formed from the ID + curve
   params and hashed into the message; toggle the ID and watch the signature
   and the required verifier ID move together.
3. THE CIPHERTEXT + THE BREAK — the two byte-orders side by side, and the
   nonce-reuse recovery.

## §1.2 SECURITY / CORRECTNESS INVARIANTS (beat features on conflict)

INV-1  Sign/verify matches the GM/T 0003.5 / GB/T 32918.5 Annex A vector
       (message "message digest", ID "ALICE123@YAHOO.COM", the pinned k).
       Encrypt/decrypt matches the Annex C vector (message "encryption
       standard"). Pin both as fixtures. Port from a reference; do not
       hand-transcribe the 130-hex strings — byte equality is the acceptance
       test (see ARCHITECTURE).
INV-2  Z_A is recomputed on screen from the displayed ID and curve parameters,
       and the signature verifies ONLY when the verifier uses the same ID.
       Changing the ID in the signer and not the verifier must make verify FAIL
       — asserted against the rendered verdict, not a flag.
INV-3  Encrypt→decrypt round-trips in BOTH orders. A ciphertext produced in
       C1C3C2 fed to a C1C2C3 decoder must FAIL (and vice-versa), and the page
       must name the order mismatch as the cause — this is the interop lesson,
       executed not asserted.
INV-4  Nonce-reuse recovery: two signatures over different messages under one k
       recover d, and the recovered d re-derives the public key byte-for-byte.
       The page's REAL verifier accepts both signatures first.
INV-5  MUTATION GATE (§4.1c/§4.1d): perturbing any curve parameter, the Z_A
       construction, or the recovery arithmetic must make the owning invariant
       FAIL in CI. Sticky-red in the UI is a teaching affordance, not the test.
INV-6  The deliberately-vulnerable nonce-reuse path is isolated in its own
       module, never the default, and visibly marked broken (§1 isolation rule).
INV-7  Every negative claim in shipped copy carries a §4.1d fixture. In
       particular the "two orders are an interop failure, not a weakness"
       framing and the "SM2 nonce reuse is as fatal as ECDSA's" framing.

## §1.3 ARCHITECTURE

ALGORITHM SOURCE (normative):
Hand-roll the inspectable SM2 sign / verify / encrypt / decrypt and the Z_A
digest on top of @noble/curves (instantiate the SM2 curve with weierstrass()
from the standard's parameters). Cross-check every result against two
independent references so the claims suite has a second route:
  - @li0ard/sm2  (GB/T 32918-2016, pure TS) — sign/verify/encrypt/exchange
  - sm-crypto    — has cipherMode 1 = C1C3C2 (default), 0 = C1C2C3, and userId
                   (default 1234567812345678); use it to anchor the two-order
                   demo and the default-ID behavior.
KAT source: the GM/T 0003 Annex A (sign) and Annex C (encrypt) vectors as pinned
in OpenSSL's `test/sm2_internal_test.c`. Port the fixtures from there; INV-1 byte
equality is the acceptance criterion, not a hand-copied string.

Small, separately-testable modules: `src/sm2/curve.ts`, `sm2.ts` (sign/verify/
enc/dec), `zdigest.ts` (Z_A), `types.ts`, `src/attack/nonce-reuse.ts` (isolated),
`src/ui/`. Keep the inspectable crypto out of the UI layer. Everything
client-side, no build step beyond the catalog default.

## §1.4 UI

PANE 1 — The Curve
  Build-and-verify: show the SM2 curve parameters loaded from the standard, then
  a "run Annex A / Annex C vectors" control that reports pass/fail against the
  pinned fixtures. Plain-language intro ("what SM2 is, why China has its own
  public-key standard") above the first hex.

PANE 2 — The Signature (HEADLINE)
  Show Z_A assembling: ENTL || ID || a || b || Gx || Gy || xA || yA, hashed by
  SM3, then prepended to the message before the signature equation. A single ID
  field the visitor edits. Two verifier toggles: "verify with same ID" (accepts)
  and "verify with default ID 1234567812345678" (rejects, unless the signer used
  it). SHOW the ID flowing into the hash — do not narrate it in prose the picture
  already makes. The signature equation r = (e + x1) mod n, s = (1+d)^-1 (k - r d)
  mod n inside a <details> disclosure.

PANE 3 — The Ciphertext + The Break
  a. Two-order view: encrypt once, render the ciphertext as C1 | C3 | C2 and as
     C1 | C2 | C3 side by side, same bytes regrouped. A decoder selector; feeding
     the wrong order fails and names the mismatch. This is the migration lesson.
  b. Break-it-yourself: reuse one nonce k across two messages; the page's REAL
     verifier accepts both; then recover d and show it re-derives the public key.
     Same shape as ecdsa-forge / schnorr-forge — mark the reused-nonce mode as the
     broken path, never the default.

REAL-WORLD box: SM2 is the signature and the curve behind RFC 8998's ShangMi
TLS 1.3 suites (TLS_SM4_GCM_SM3 / TLS_SM4_CCM_SM3, the sm2sig_sm3 scheme, the
curveSM2 group). Read the exact codepoints out of RFC 8998 and pin them — do not
assert them from memory.

HERO — three text roles kept distinct:
  subtitle    : spec label only (see NEW DEMO BRIEF)
  description : what the demo demonstrates — SM2 sign/encrypt with the ID prefix
                and the two ciphertext orders
  why it matters: adopting a national crypto suite is not a curve swap — the
                signature binds an identity and the ciphertext ships two ways

## §1.5 VISUAL SEMANTICS

green   = verifier accepts / order round-trips / KAT matches
red, sticky = verify rejected, order mismatch, or KAT fail; persists so the
          visitor can find the exact failure
alarm   = a forged-but-accepted result in the nonce-reuse pane reads as ALARM,
          never green success
selected= the ID / order currently under inspection
Never convey state by color alone — icon + text + color throughout. No
decorative motion. Never draw the ID flowing into a signature that then verifies
under a different ID.

## §1.6 EDGE CASES

- Empty / non-default ID: ENTL_A is the bit-length of ID_A; get the two-byte
  length prefix right or Z_A is wrong. Wire ENTL as a claims assertion.
- k = 0 or r = 0 or r + k = n during signing: the standard restarts; show the
  restart, do not throw.
- (1 + d) not invertible mod n: standard forbids d = n − 1; reject at keygen.
- Ciphertext with C1 not on the curve (point validation on decrypt): fail closed.
- Wrong-order decode must fail cleanly and name the cause, not throw.
- Nonce-reuse recovery when the two messages are identical: no two independent
  equations, so recovery does not apply — say so rather than showing a bogus d.

## §1.7 EXTENSION SEAMS

- SM2 key exchange (SM2-2) as a fourth pane. Mark `// [extension] point`.
- SM9 (identity-based, pairing) as a sibling lab, not built here.
- An RFC 8998 handshake walkthrough linking to the tls-handshake lab.

## VERIFY BEFORE WRITING COPY — do not assert, grep

- grep CATEGORIES and report the resulting chip-bar split; propose placement from
  {ENCRYPTION | SIGNATURES | KEY EXCHANGE}. Do not state a category is new.
- grep the catalog for existing SM2 / ShangMi / GM-standard coverage and report
  overlaps before any "first"/"only" phrasing, in any revision.
- grep for crypto-lab-sm2-* name collisions before creating the repo.
- Read the SM2 curve parameters out of GM/T 0003.5 / GB/T 32918.5 Annex and
  record them here; cross-check Gx,Gy against @noble/curves.
- Read RFC 8998 and pin the SM cipher-suite codepoints, the sm2sig_sm3 scheme id,
  and the curveSM2 group id here before the real-world box claims any of them.
- Confirm the default ID 1234567812345678 in RFC 8998 §3.2.1.

## CI GATES (existing mechanisms — reference, do not reinvent)

- `e2e/claims.spec.ts` — §4.1b cross-checks + independent re-derivations (the
  hand-rolled result vs @li0ard/sm2 vs the pinned KAT), §4.1c mutation discipline,
  §4.1d negative-claim scope tests (the two-order and nonce-reuse claims).
- §4 axe/WCAG gate. §5 README section list. §6.1/6.2 dependabot grouping,
  auto-merge, deploy dispatch.
- §4.1d names CLAIMS.yaml, THREAT-MODEL.md and a second-language verifier as the
  things NOT to build. Do not build them here.

## CITATIONS (verify each against the primary source before it ships)

- GB/T 32918-2016 / GM/T 0003-2012, SM2 elliptic-curve public-key algorithm
  (parts: .1 general, .2 signature, .3 key exchange, .4 encryption, .5 params).
  Annex A = signature test vector, Annex C = encryption test vector.
- GB/T 32905 / GM/T 0004, SM3 hash (used as SM2's required hash).
- RFC 8998, "ShangMi (SM) Cipher Suites for TLS 1.3", P. Yang, ed., 2021 —
  §3.2.1 for the default SM2 ID; §2–3 for the suites/scheme/group codepoints.
- OpenSSL `test/sm2_internal_test.c` — executable pin of the GM/T 0003 Annex A/C
  vectors and the default ID; use as the fixture source and cross-check.
- @li0ard/sm2 (GB/T 32918-2016, pure TS) and sm-crypto — independent references.