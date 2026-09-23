import { describe, expect, it } from 'vitest';

import { bytesToBigInt } from '../sm2/bytes';
import {
  ANNEX_MESSAGE,
  ANNEX_NONCE,
  ANNEX_PRIVATE_KEY,
  ANNEX_PUBLIC_KEY,
} from '../sm2/fixtures';
import { signSm2, verifySm2 } from '../sm2/sm2';
import { recoverPrivateKeyFromReusedNonce } from './nonce-reuse';

describe('deliberately broken SM2 nonce reuse', () => {
  it('recovers d from two signatures accepted by the real verifier', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const secondMessage = new TextEncoder().encode('different message, same fatal nonce');
    const first = signSm2(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, { nonceSource: () => nonce });
    const second = signSm2(ANNEX_PRIVATE_KEY, secondMessage, { nonceSource: () => nonce });

    expect(verifySm2(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, first.signature).accepted).toBe(true);
    expect(verifySm2(ANNEX_PUBLIC_KEY, secondMessage, second.signature).accepted).toBe(true);

    const recovery = recoverPrivateKeyFromReusedNonce(first.signature, second.signature);
    expect(recovery.recovered).toBe(true);
    if (!recovery.recovered) {
      throw new Error(recovery.reason);
    }

    expect(recovery.privateKey).toBe(bytesToBigInt(ANNEX_PRIVATE_KEY));
    expect(recovery.publicKey).toEqual(ANNEX_PUBLIC_KEY);
  });

  it('refuses identical signatures because they are not independent equations', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const signature = signSm2(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, {
      nonceSource: () => nonce,
    }).signature;

    expect(recoverPrivateKeyFromReusedNonce(signature, signature)).toEqual({
      recovered: false,
      reason: 'Identical signatures do not provide two independent equations.',
    });
  });
});