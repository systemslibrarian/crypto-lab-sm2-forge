import { publicKeyFromPrivate, SM2_CURVE, SM2Point } from '../sm2/curve';
import type { Sm2Signature } from '../sm2/types';

export type NonceReuseRecovery =
  | { recovered: true; privateKey: bigint; publicKey: Uint8Array }
  | { recovered: false; reason: string };

function mod(value: bigint): bigint {
  const reduced = value % SM2_CURVE.n;
  return reduced >= 0n ? reduced : reduced + SM2_CURVE.n;
}

// Deliberately broken teaching path: never call this from normal signing.
export function recoverPrivateKeyFromReusedNonce(
  first: Sm2Signature,
  second: Sm2Signature,
): NonceReuseRecovery {
  if (first.r === second.r && first.s === second.s) {
    return {
      recovered: false,
      reason: 'Identical signatures do not provide two independent equations.',
    };
  }

  const denominator = mod(first.s + first.r - second.s - second.r);
  if (denominator === 0n) {
    return {
      recovered: false,
      reason: 'The two equations are dependent, so the private key is not recoverable from this pair.',
    };
  }

  const privateKey = mod((second.s - first.s) * SM2Point.Fn.inv(denominator));
  if (privateKey <= 0n || privateKey >= SM2_CURVE.n - 1n) {
    return {
      recovered: false,
      reason: 'The recovered scalar is outside the valid SM2 private-key range.',
    };
  }

  return {
    recovered: true,
    privateKey,
    publicKey: publicKeyFromPrivate(privateKey),
  };
}