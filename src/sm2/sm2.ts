import { sm3 } from '@li0ard/sm3';
import { randomBytes } from '@noble/curves/utils.js';

import {
  bigIntToBytes,
  bytesToBigInt,
  concatBytes,
  equalBytes,
  FIELD_BYTES,
  xorBytes,
} from './bytes';
import {
  assertPrivateKey,
  fieldElementToBytes,
  publicKeyFromPrivate,
  SM2_CURVE,
  SM2Point,
} from './curve';
import type {
  CiphertextOrder,
  SignRestartReason,
  Sm2CiphertextComponents,
  Sm2DecryptionResult,
  Sm2EncryptionResult,
  Sm2Signature,
  Sm2SignTrace,
  Sm2VerifyResult,
} from './types';
import { DEFAULT_SM2_ID, identityDigest } from './zdigest';

const MAX_NONCE_ATTEMPTS = 1_024;

export interface NonceOptions {
  nonceSource?: () => bigint;
}

export interface SignOptions extends NonceOptions {
  identity?: Uint8Array;
}

export interface EncryptOptions extends NonceOptions {
  order?: CiphertextOrder;
}

function mod(value: bigint, modulus: bigint): bigint {
  const reduced = value % modulus;
  return reduced >= 0n ? reduced : reduced + modulus;
}

function randomScalar(): bigint {
  while (true) {
    const candidate = bytesToBigInt(randomBytes(FIELD_BYTES));
    if (candidate > 0n && candidate < SM2_CURVE.n) {
      return candidate;
    }
  }
}

function privateScalar(privateKey: bigint | Uint8Array): bigint {
  const scalar = typeof privateKey === 'bigint' ? privateKey : bytesToBigInt(privateKey);
  assertPrivateKey(scalar);
  return scalar;
}

function decodeUncompressedPoint(bytes: Uint8Array, label: string) {
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new TypeError(`${label} must be a 65-byte uncompressed point`);
  }

  const point = SM2Point.fromBytes(bytes);
  point.assertValidity();
  return point;
}

function sm3Kdf(input: Uint8Array, outputLength: number): Uint8Array {
  const output = new Uint8Array(outputLength);
  let offset = 0;
  let counter = 1;

  while (offset < outputLength) {
    const block = sm3(concatBytes(input, bigIntToBytes(BigInt(counter), 4)));
    const remaining = outputLength - offset;
    output.set(block.subarray(0, Math.min(block.length, remaining)), offset);
    offset += block.length;
    counter += 1;
  }

  return output;
}

function isAllZero(bytes: Uint8Array): boolean {
  return bytes.length > 0 && bytes.every((byte) => byte === 0);
}

export function signatureToBytes(signature: Sm2Signature): Uint8Array {
  return concatBytes(
    bigIntToBytes(signature.r, FIELD_BYTES),
    bigIntToBytes(signature.s, FIELD_BYTES),
  );
}

export function signatureFromBytes(bytes: Uint8Array): Sm2Signature {
  if (bytes.length !== FIELD_BYTES * 2) {
    throw new TypeError('SM2 signature must contain 32-byte r and s values');
  }

  return {
    r: bytesToBigInt(bytes.subarray(0, FIELD_BYTES)),
    s: bytesToBigInt(bytes.subarray(FIELD_BYTES)),
  };
}

export function signSm2(
  privateKey: bigint | Uint8Array,
  message: Uint8Array,
  options: SignOptions = {},
): Sm2SignTrace {
  const privateKeyScalar = privateScalar(privateKey);
  const publicKey = publicKeyFromPrivate(privateKeyScalar);
  const za = identityDigest(publicKey, options.identity ?? DEFAULT_SM2_ID);
  const digest = sm3(concatBytes(za, message));
  const e = bytesToBigInt(digest);
  const restarts: SignRestartReason[] = [];
  const nextNonce = options.nonceSource ?? randomScalar;

  for (let attempt = 0; attempt < MAX_NONCE_ATTEMPTS; attempt += 1) {
    const nonce = nextNonce();
    if (nonce <= 0n || nonce >= SM2_CURVE.n) {
      restarts.push('k-out-of-range');
      continue;
    }

    const noncePoint = SM2Point.BASE.multiply(nonce);
    const r = mod(e + noncePoint.x, SM2_CURVE.n);
    if (r === 0n) {
      restarts.push('r-zero');
      continue;
    }
    if (r + nonce === SM2_CURVE.n) {
      restarts.push('r-plus-k-equals-n');
      continue;
    }

    const numerator = mod(nonce - r * privateKeyScalar, SM2_CURVE.n);
    const denominatorInverse = SM2Point.Fn.inv(mod(1n + privateKeyScalar, SM2_CURVE.n));
    const s = mod(denominatorInverse * numerator, SM2_CURVE.n);
    if (s === 0n) {
      restarts.push('s-zero');
      continue;
    }

    return {
      signature: { r, s },
      publicKey,
      identityDigest: za,
      messageDigest: digest,
      nonce,
      restarts,
    };
  }

  throw new Error('SM2 signing exhausted the nonce restart limit');
}

export function verifySm2(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Sm2Signature,
  identity: Uint8Array = DEFAULT_SM2_ID,
): Sm2VerifyResult {
  if (
    signature.r <= 0n ||
    signature.r >= SM2_CURVE.n ||
    signature.s <= 0n ||
    signature.s >= SM2_CURVE.n
  ) {
    return { accepted: false, reason: 'Signature scalars are outside the valid range.' };
  }

  let point;
  try {
    point = decodeUncompressedPoint(publicKey, 'SM2 public key');
  } catch {
    return { accepted: false, reason: 'The public key is not a valid curveSM2 point.' };
  }

  const za = identityDigest(publicKey, identity);
  const e = bytesToBigInt(sm3(concatBytes(za, message)));
  const t = mod(signature.r + signature.s, SM2_CURVE.n);
  if (t === 0n) {
    return { accepted: false, reason: 'Verification stopped because (r + s) mod n is zero.', identityDigest: za };
  }

  const candidate = SM2Point.BASE.multiplyUnsafe(signature.s).add(point.multiplyUnsafe(t));
  if (candidate.is0()) {
    return { accepted: false, reason: 'Verification produced the point at infinity.', identityDigest: za };
  }

  const computedR = mod(e + candidate.x, SM2_CURVE.n);
  return {
    accepted: computedR === signature.r,
    reason:
      computedR === signature.r
        ? 'The verifier recomputed the same r value.'
        : 'The verifier recomputed a different r value; the message, identity, or signature changed.',
    identityDigest: za,
    computedR,
  };
}

export function serializeCiphertext(
  components: Sm2CiphertextComponents,
  order: CiphertextOrder,
): Uint8Array {
  return order === 'C1C3C2'
    ? concatBytes(components.c1, components.c3, components.c2)
    : concatBytes(components.c1, components.c2, components.c3);
}

function parseCiphertext(
  ciphertext: Uint8Array,
  order: CiphertextOrder,
): Sm2CiphertextComponents | undefined {
  if (ciphertext.length < 97) {
    return undefined;
  }

  const c1 = ciphertext.slice(0, 65);
  const payloadLength = ciphertext.length - 97;
  if (order === 'C1C3C2') {
    return {
      c1,
      c3: ciphertext.slice(65, 97),
      c2: ciphertext.slice(97),
    };
  }

  return {
    c1,
    c2: ciphertext.slice(65, 65 + payloadLength),
    c3: ciphertext.slice(65 + payloadLength),
  };
}

export function encryptSm2(
  publicKey: Uint8Array,
  plaintext: Uint8Array,
  options: EncryptOptions = {},
): Sm2EncryptionResult {
  const recipient = decodeUncompressedPoint(publicKey, 'SM2 public key');
  const nextNonce = options.nonceSource ?? randomScalar;
  const order = options.order ?? 'C1C3C2';

  for (let attempt = 0; attempt < MAX_NONCE_ATTEMPTS; attempt += 1) {
    const nonce = nextNonce();
    if (nonce <= 0n || nonce >= SM2_CURVE.n) {
      continue;
    }

    const c1 = SM2Point.BASE.multiply(nonce).toBytes(false);
    const shared = recipient.multiply(nonce);
    const x2 = fieldElementToBytes(shared.x);
    const y2 = fieldElementToBytes(shared.y);
    const mask = sm3Kdf(concatBytes(x2, y2), plaintext.length);
    if (isAllZero(mask)) {
      continue;
    }

    const components = {
      c1,
      c2: xorBytes(plaintext, mask),
      c3: sm3(concatBytes(x2, plaintext, y2)),
    };

    return {
      ...components,
      ciphertext: serializeCiphertext(components, order),
      nonce,
      order,
      restarts: attempt,
    };
  }

  throw new Error('SM2 encryption exhausted the nonce restart limit');
}

export function decryptSm2(
  privateKey: bigint | Uint8Array,
  ciphertext: Uint8Array,
  order: CiphertextOrder,
): Sm2DecryptionResult {
  const components = parseCiphertext(ciphertext, order);
  if (!components) {
    return {
      ok: false,
      code: 'MALFORMED_CIPHERTEXT',
      reason: 'Ciphertext is too short to contain C1, C3, and the payload.',
    };
  }

  let c1Point;
  try {
    c1Point = decodeUncompressedPoint(components.c1, 'C1');
  } catch {
    return {
      ok: false,
      code: 'INVALID_C1',
      reason: 'C1 is not a valid point on curveSM2; decryption failed closed.',
    };
  }

  const scalar = privateScalar(privateKey);
  const shared = c1Point.multiply(scalar);
  const x2 = fieldElementToBytes(shared.x);
  const y2 = fieldElementToBytes(shared.y);
  const mask = sm3Kdf(concatBytes(x2, y2), components.c2.length);
  if (isAllZero(mask)) {
    return {
      ok: false,
      code: 'ZERO_KDF',
      reason: 'The SM3 KDF produced an all-zero mask, so this ciphertext is rejected.',
    };
  }

  const plaintext = xorBytes(components.c2, mask);
  const expectedC3 = sm3(concatBytes(x2, plaintext, y2));
  if (!equalBytes(expectedC3, components.c3)) {
    return {
      ok: false,
      code: 'INTEGRITY_CHECK_FAILED',
      reason: 'SM3 integrity check failed: the ciphertext is corrupt or decoded with the wrong byte order.',
    };
  }

  return { ok: true, plaintext, components };
}