export interface IdentityDigestPart {
  label: 'ENTL' | 'ID' | 'a' | 'b' | 'Gx' | 'Gy' | 'xA' | 'yA';
  bytes: Uint8Array;
}

export interface IdentityDigestTrace {
  parts: IdentityDigestPart[];
  input: Uint8Array;
  digest: Uint8Array;
}

export interface Sm2Signature {
  r: bigint;
  s: bigint;
}

export type CiphertextOrder = 'C1C3C2' | 'C1C2C3';

// [extension] point: SM2 key exchange gets its own types and fourth pane.

export type SignRestartReason = 'k-out-of-range' | 'r-zero' | 'r-plus-k-equals-n' | 's-zero';

export interface Sm2SignTrace {
  signature: Sm2Signature;
  publicKey: Uint8Array;
  identityDigest: Uint8Array;
  messageDigest: Uint8Array;
  nonce: bigint;
  restarts: SignRestartReason[];
}

export interface Sm2VerifyResult {
  accepted: boolean;
  reason: string;
  identityDigest?: Uint8Array;
  computedR?: bigint;
}

export interface Sm2CiphertextComponents {
  c1: Uint8Array;
  c2: Uint8Array;
  c3: Uint8Array;
}

export interface Sm2EncryptionResult extends Sm2CiphertextComponents {
  ciphertext: Uint8Array;
  nonce: bigint;
  order: CiphertextOrder;
  restarts: number;
}

export type Sm2DecryptionResult =
  | { ok: true; plaintext: Uint8Array; components: Sm2CiphertextComponents }
  | {
      ok: false;
      code: 'MALFORMED_CIPHERTEXT' | 'INVALID_C1' | 'ZERO_KDF' | 'INTEGRITY_CHECK_FAILED';
      reason: string;
    };