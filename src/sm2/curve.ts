import { weierstrass } from '@noble/curves/abstract/weierstrass.js';

import { bigIntToBytes, bytesToBigInt, FIELD_BYTES } from './bytes';

export const SM2_CURVE_HEX = Object.freeze({
  p: 'fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff',
  a: 'fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc',
  b: '28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93',
  n: 'fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123',
  gx: '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7',
  gy: 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
  h: '01',
});

export const SM2_CURVE = Object.freeze({
  p: BigInt(`0x${SM2_CURVE_HEX.p}`),
  a: BigInt(`0x${SM2_CURVE_HEX.a}`),
  b: BigInt(`0x${SM2_CURVE_HEX.b}`),
  n: BigInt(`0x${SM2_CURVE_HEX.n}`),
  Gx: BigInt(`0x${SM2_CURVE_HEX.gx}`),
  Gy: BigInt(`0x${SM2_CURVE_HEX.gy}`),
  h: 1n,
});

export const SM2Point = weierstrass(SM2_CURVE);

export function assertPrivateKey(privateKey: bigint): void {
  if (privateKey <= 0n || privateKey >= SM2_CURVE.n - 1n) {
    throw new RangeError('SM2 private key must satisfy 1 <= d <= n - 2');
  }
}

export function publicKeyFromPrivate(privateKey: bigint | Uint8Array): Uint8Array {
  const scalar = typeof privateKey === 'bigint' ? privateKey : bytesToBigInt(privateKey);
  assertPrivateKey(scalar);
  return SM2Point.BASE.multiply(scalar).toBytes(false);
}

export function fieldElementToBytes(value: bigint): Uint8Array {
  return bigIntToBytes(value, FIELD_BYTES);
}