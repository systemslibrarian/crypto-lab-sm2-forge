# SM2 Forge

**GB/T 32918 · GM/T 0003 · RFC 8998**

A browser-only lab for SM2 signatures and public-key encryption. It builds the required curve, exposes the identity digest that precedes every signature, compares both deployed ciphertext byte orders, and demonstrates private-key recovery when a signer reuses one nonce.

> **Not production cryptography — a teaching demo.** Secret values are deliberately inspectable, JavaScript does not promise constant-time execution, and nothing is persisted or sent to a backend.

## What It Is

SM2 is a family of elliptic-curve algorithms standardized in China. This lab hand-rolls the inspectable signing, verification, encryption, decryption, Z_A digest, and nonce-recovery equations over the fixed curveSM2 parameters using `@noble/curves`; SM3 comes from `@li0ard/sm3`.

The signature's distinguishing step is:

```text
Z_A = SM3(ENTL_A || ID_A || a || b || Gx || Gy || xA || yA)
e   = SM3(Z_A || message)
```

The security target is correct SM2 signatures and authenticated SM2 ciphertexts under strict point validation. It does not implement SM2 key exchange, SM4, SM3 internals, or a TLS handshake, and conformance tests do not make this code suitable for protecting real keys.

## Exhibits

1. **The Curve** — Load RFC 8998's curveSM2 parameters and run the GM/T 0003.5 / GB/T 32918.5 Annex A signature and Annex C encryption fixtures byte-for-byte before later panes unlock.
2. **The Signature** — Edit the signer ID, watch ENTL and all eight Z_A inputs assemble, sign a message, then verify with either the same ID or the RFC default `1234567812345678`.
3. **The Ciphertext + The Break** — Regroup one ciphertext as standard `C1C3C2` or earlier-draft `C1C2C3`, execute matching and mismatched decoders, then enter the isolated broken path where two valid signatures reuse one nonce and reveal the private key.

## When to Use It

- Use the lab to understand SM2 migrations, identity configuration, byte-order interoperability, and signing-nonce failures.
- Use an audited SM2 implementation that fixes the ID and serialization contract explicitly in production.
- Do **not** use this teaching implementation for production keys, certificates, TLS, or regulated deployments.
- Do **not** treat a valid signature as evidence that its nonce generator was safe.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-sm2-forge/**

Run the published vectors, change the signing identity, cross the two ciphertext layouts, and recover the demonstration key entirely in the browser.

## What Can Go Wrong

- **Identity mismatch** — a signer and verifier that use different IDs compute different Z_A values and verification fails.
- **Serialization mismatch** — `C1C3C2` bytes fed to a `C1C2C3` decoder fail the SM3 integrity check even though both layouts are valid conventions.
- **Nonce reuse** — two signatures over different messages under one `k` expose `d`; the recovered scalar re-derives the victim public key exactly.
- **Malformed C1** — decryption rejects a point that is not on curveSM2 before deriving a shared point.
- **Invalid private key** — SM2 excludes `d = n - 1` because `(1 + d)` would not be invertible modulo `n`.

## Real-World Usage

RFC 8998 defines the informational ShangMi TLS 1.3 profile: `TLS_SM4_GCM_SM3` (`0x00C6`), `TLS_SM4_CCM_SM3` (`0x00C7`), `sm2sig_sm3` (`0x0708`), and `curveSM2` (group `41`). Its certificate-signature default ID is the ASCII string `1234567812345678`; other SM2 contexts can use different IDs and must agree on them.

## How to Run Locally

```bash
npm install
npm run dev
npm test
npm run build
npm run test:e2e
npm run test:a11y
```

The Vite development URL is `http://localhost:5173/crypto-lab-sm2-forge/` when that port is free. Playwright builds and serves the production bundle on fleet-unique port `4607`.

## Related Demos

- [ECDSA Forge](https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/) — compare another nonce-sensitive elliptic-curve signature.
- [Schnorr Forge](https://systemslibrarian.github.io/crypto-lab-schnorr-forge/) — compare linear signing and its nonce-reuse recovery.
- [TLS Handshake](https://systemslibrarian.github.io/crypto-lab-tls-handshake/) — place RFC 8998's identifiers in TLS context.
- [World Hashes](https://systemslibrarian.github.io/crypto-lab-world-hashes/) — inspect hash functions; this lab uses SM3 without dissecting it.

## Build & Verify

- **12 unit tests** under `src/**/*.test.ts` cover curve construction, ENTL/Z_A, signing, verification, both ciphertext orders, malformed C1 rejection, and nonce-reuse recovery.
- **2 published KAT fixtures** in [`src/sm2/fixtures.ts`](src/sm2/fixtures.ts) reproduce OpenSSL's executable pins of GM/T 0003.5 / GB/T 32918.5 Annex A and Annex C.
- Every signature and encryption path is cross-checked with `@li0ard/sm2`; `sm-crypto` independently verifies the default ID and both cipher-mode serializations.
- **7 rendered claims tests** in [`e2e/claims.spec.ts`](e2e/claims.spec.ts) check the page's verdicts, retirement behavior, ENTL computation, order mismatch, and both negative-claim fixtures.
- **2 full accessibility drives** in [`e2e/a11y.spec.ts`](e2e/a11y.spec.ts) scan desktop and 380px states with axe, arithmetic text contrast, non-text contrast, keyboard reachability, focus visibility, and reflow checks.

## Performance

All arithmetic runs client-side with no network calls after the static assets load. The current production bundle is approximately 19 kB gzip JavaScript and 4 kB gzip CSS.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*