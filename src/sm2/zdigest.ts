import { sm3 } from '@li0ard/sm3';

import { concatBytes } from './bytes';
import { fieldElementToBytes, SM2_CURVE, SM2Point } from './curve';
import type { IdentityDigestPart, IdentityDigestTrace } from './types';

export const DEFAULT_SM2_ID = new TextEncoder().encode('1234567812345678');
export const MAX_ID_BYTES = 8191;

export function encodeIdentityBitLength(identity: Uint8Array): Uint8Array {
  if (identity.length > MAX_ID_BYTES) {
    throw new RangeError('SM2 identity is too long for its two-byte bit-length prefix');
  }

  const bitLength = identity.length * 8;
  return new Uint8Array([bitLength >>> 8, bitLength & 0xff]);
}

export function createIdentityDigestTrace(
  publicKey: Uint8Array,
  identity: Uint8Array = DEFAULT_SM2_ID,
): IdentityDigestTrace {
  const point = SM2Point.fromBytes(publicKey);
  point.assertValidity();

  const parts: IdentityDigestPart[] = [
    { label: 'ENTL', bytes: encodeIdentityBitLength(identity) },
    { label: 'ID', bytes: identity },
    { label: 'a', bytes: fieldElementToBytes(SM2_CURVE.a) },
    { label: 'b', bytes: fieldElementToBytes(SM2_CURVE.b) },
    { label: 'Gx', bytes: fieldElementToBytes(SM2_CURVE.Gx) },
    { label: 'Gy', bytes: fieldElementToBytes(SM2_CURVE.Gy) },
    { label: 'xA', bytes: fieldElementToBytes(point.x) },
    { label: 'yA', bytes: fieldElementToBytes(point.y) },
  ];
  const input = concatBytes(...parts.map((part) => part.bytes));

  return { parts, input, digest: sm3(input) };
}

export function identityDigest(
  publicKey: Uint8Array,
  identity: Uint8Array = DEFAULT_SM2_ID,
): Uint8Array {
  return createIdentityDigestTrace(publicKey, identity).digest;
}