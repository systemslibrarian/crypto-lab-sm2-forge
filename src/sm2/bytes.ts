export const FIELD_BYTES = 32;

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const length = arrays.reduce((total, array) => total + array.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;

  for (const array of arrays) {
    output.set(array, offset);
    offset += array.length;
  }

  return output;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  const hex = bytesToHex(bytes);
  return hex.length === 0 ? 0n : BigInt(`0x${hex}`);
}

export function bigIntToBytes(value: bigint, length = FIELD_BYTES): Uint8Array {
  if (value < 0n) {
    throw new RangeError('Cannot encode a negative integer');
  }

  const hex = value.toString(16).padStart(length * 2, '0');
  if (hex.length > length * 2) {
    throw new RangeError(`Integer does not fit in ${length} bytes`);
  }

  return hexToBytes(hex);
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replaceAll(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new TypeError('Expected an even-length hexadecimal string');
  }

  return Uint8Array.from(normalized.match(/.{2}/g) ?? [], (byte) => Number.parseInt(byte, 16));
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

export function xorBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length !== right.length) {
    throw new RangeError('XOR operands must have equal lengths');
  }

  return Uint8Array.from(left, (byte, index) => byte ^ right[index]);
}