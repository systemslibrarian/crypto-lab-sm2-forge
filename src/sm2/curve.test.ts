import { getPublicKey } from '@li0ard/sm2';
import { Z as referenceIdentityDigest } from '@li0ard/sm2/dist/utils.js';
import { describe, expect, it } from 'vitest';

import { bytesToHex } from './bytes';
import { publicKeyFromPrivate, SM2_CURVE_HEX, SM2Point } from './curve';
import { ANNEX_PRIVATE_KEY, ANNEX_PUBLIC_KEY } from './fixtures';
import {
  createIdentityDigestTrace,
  DEFAULT_SM2_ID,
  encodeIdentityBitLength,
  MAX_ID_BYTES,
} from './zdigest';

describe('curveSM2', () => {
  it('loads the exact GB/T 32918.5 parameters and generator', () => {
    expect(SM2Point.BASE.toHex(false)).toBe(`04${SM2_CURVE_HEX.gx}${SM2_CURVE_HEX.gy}`);
    expect(() => SM2Point.BASE.assertValidity()).not.toThrow();
  });

  it('derives the Annex A public key byte-for-byte', () => {
    const publicKey = publicKeyFromPrivate(ANNEX_PRIVATE_KEY);

    expect(publicKey).toEqual(ANNEX_PUBLIC_KEY);
    expect(publicKey).toEqual(getPublicKey(ANNEX_PRIVATE_KEY));
  });
});

describe('SM2 identity digest', () => {
  it('encodes ENTL as a two-byte big-endian bit length', () => {
    expect(bytesToHex(encodeIdentityBitLength(new Uint8Array()))).toBe('0000');
    expect(bytesToHex(encodeIdentityBitLength(DEFAULT_SM2_ID))).toBe('0080');
    expect(bytesToHex(encodeIdentityBitLength(new Uint8Array(MAX_ID_BYTES)))).toBe('fff8');
    expect(() => encodeIdentityBitLength(new Uint8Array(MAX_ID_BYTES + 1))).toThrow(/too long/);
  });

  it('matches an independent Z_A implementation', () => {
    const trace = createIdentityDigestTrace(ANNEX_PUBLIC_KEY, DEFAULT_SM2_ID);

    expect(trace.parts.map((part) => part.label)).toEqual([
      'ENTL',
      'ID',
      'a',
      'b',
      'Gx',
      'Gy',
      'xA',
      'yA',
    ]);
    expect(trace.digest).toEqual(referenceIdentityDigest(ANNEX_PUBLIC_KEY, DEFAULT_SM2_ID));
  });
});