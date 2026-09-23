import {
  CipherMode as ReferenceCipherMode,
  decrypt as referenceDecrypt,
  encrypt as referenceEncrypt,
  sign as referenceSign,
  verify as referenceVerify,
} from '@li0ard/sm2';
import { sm2 as secondReference } from 'sm-crypto';
import { describe, expect, it } from 'vitest';

import { bytesToBigInt, bytesToHex, concatBytes, hexToBytes } from './bytes';
import {
  ANNEX_CIPHERTEXT,
  ANNEX_ENCRYPTION_MESSAGE,
  ANNEX_MESSAGE,
  ANNEX_NONCE,
  ANNEX_PRIVATE_KEY,
  ANNEX_PUBLIC_KEY,
  ANNEX_SIGNATURE,
} from './fixtures';
import {
  decryptSm2,
  encryptSm2,
  serializeCiphertext,
  signatureToBytes,
  signSm2,
  verifySm2,
} from './sm2';
import { DEFAULT_SM2_ID } from './zdigest';

describe('SM2 signature', () => {
  it('matches the GM/T 0003.5 Annex A signature byte-for-byte', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const trace = signSm2(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, { nonceSource: () => nonce });
    const signature = signatureToBytes(trace.signature);

    expect(trace.signature).toEqual(ANNEX_SIGNATURE);
    expect(signature).toEqual(referenceSign(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, DEFAULT_SM2_ID, ANNEX_NONCE));
    expect(verifySm2(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, trace.signature).accepted).toBe(true);
    expect(referenceVerify(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, signature, DEFAULT_SM2_ID)).toBe(true);
    expect(
      secondReference.doVerifySignature(
        Array.from(ANNEX_MESSAGE),
        bytesToHex(signature),
        bytesToHex(ANNEX_PUBLIC_KEY),
      ),
    ).toBe(true);

    const secondReferenceSignature = secondReference.doSignature(
      Array.from(ANNEX_MESSAGE),
      bytesToHex(ANNEX_PRIVATE_KEY),
    );
    expect(
      verifySm2(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, {
        r: BigInt(`0x${secondReferenceSignature.slice(0, 64)}`),
        s: BigInt(`0x${secondReferenceSignature.slice(64)}`),
      }).accepted,
    ).toBe(true);
  });

  it('rejects a signature when the verifier uses a different identity', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const signerId = new TextEncoder().encode('ALICE123@YAHOO.COM');
    const trace = signSm2(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, {
      identity: signerId,
      nonceSource: () => nonce,
    });

    expect(verifySm2(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, trace.signature, signerId).accepted).toBe(true);
    expect(verifySm2(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, trace.signature, DEFAULT_SM2_ID).accepted).toBe(false);
    expect(
      secondReference.doVerifySignature(
        Array.from(ANNEX_MESSAGE),
        bytesToHex(signatureToBytes(trace.signature)),
        bytesToHex(ANNEX_PUBLIC_KEY),
        { userId: 'ALICE123@YAHOO.COM' },
      ),
    ).toBe(true);
  });

  it('restarts instead of throwing when k is zero', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const candidates = [0n, nonce];
    const trace = signSm2(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, {
      nonceSource: () => candidates.shift() ?? nonce,
    });

    expect(trace.restarts).toEqual(['k-out-of-range']);
    expect(trace.signature).toEqual(ANNEX_SIGNATURE);
  });
});

describe('SM2 encryption', () => {
  it('matches the GM/T 0003.5 Annex C components byte-for-byte', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const encrypted = encryptSm2(ANNEX_PUBLIC_KEY, ANNEX_ENCRYPTION_MESSAGE, {
      order: 'C1C3C2',
      nonceSource: () => nonce,
    });
    const expected = serializeCiphertext(ANNEX_CIPHERTEXT, 'C1C3C2');

    expect(encrypted.c1).toEqual(ANNEX_CIPHERTEXT.c1);
    expect(encrypted.c2).toEqual(ANNEX_CIPHERTEXT.c2);
    expect(encrypted.c3).toEqual(ANNEX_CIPHERTEXT.c3);
    expect(encrypted.ciphertext).toEqual(expected);
    expect(encrypted.ciphertext).toEqual(
      referenceEncrypt(
        ANNEX_PUBLIC_KEY,
        ANNEX_ENCRYPTION_MESSAGE,
        ReferenceCipherMode.C1C3C2,
        ANNEX_NONCE,
      ),
    );
  });

  it('round-trips both layouts and rejects the wrong decoder order', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);

    for (const order of ['C1C3C2', 'C1C2C3'] as const) {
      const encrypted = encryptSm2(ANNEX_PUBLIC_KEY, ANNEX_ENCRYPTION_MESSAGE, {
        order,
        nonceSource: () => nonce,
      });
      const decrypted = decryptSm2(ANNEX_PRIVATE_KEY, encrypted.ciphertext, order);
      const wrongOrder = order === 'C1C3C2' ? 'C1C2C3' : 'C1C3C2';
      const rejected = decryptSm2(ANNEX_PRIVATE_KEY, encrypted.ciphertext, wrongOrder);

      expect(decrypted.ok && decrypted.plaintext).toEqual(ANNEX_ENCRYPTION_MESSAGE);
      expect(rejected).toMatchObject({ ok: false, code: 'INTEGRITY_CHECK_FAILED' });
      expect(() =>
        referenceDecrypt(
          ANNEX_PRIVATE_KEY,
          encrypted.ciphertext,
          order === 'C1C3C2' ? ReferenceCipherMode.C1C3C2 : ReferenceCipherMode.C1C2C3,
        ),
      ).not.toThrow();

      const secondReferenceMode = order === 'C1C3C2' ? 1 : 0;
      expect(
        secondReference.doDecrypt(
          bytesToHex(encrypted.ciphertext).slice(2),
          bytesToHex(ANNEX_PRIVATE_KEY),
          secondReferenceMode,
          { output: 'array' },
        ),
      ).toEqual(Array.from(ANNEX_ENCRYPTION_MESSAGE));

      const secondReferenceCiphertext = secondReference.doEncrypt(
        Array.from(ANNEX_ENCRYPTION_MESSAGE),
        bytesToHex(ANNEX_PUBLIC_KEY),
        secondReferenceMode,
      );
      const independentlyDecrypted = decryptSm2(
        ANNEX_PRIVATE_KEY,
        hexToBytes(`04${secondReferenceCiphertext}`),
        order,
      );
      expect(independentlyDecrypted.ok && independentlyDecrypted.plaintext).toEqual(
        ANNEX_ENCRYPTION_MESSAGE,
      );
    }
  });

  it('fails closed when C1 is not on the curve', () => {
    const malformed = concatBytes(new Uint8Array(65).fill(0x04), new Uint8Array(32));
    expect(decryptSm2(ANNEX_PRIVATE_KEY, malformed, 'C1C3C2')).toMatchObject({
      ok: false,
      code: 'INVALID_C1',
    });
  });
});