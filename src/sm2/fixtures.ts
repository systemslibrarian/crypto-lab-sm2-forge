import { hexToBytes } from './bytes';

export const ANNEX_MESSAGE = new TextEncoder().encode('message digest');
export const ANNEX_ENCRYPTION_MESSAGE = new TextEncoder().encode('encryption standard');
export const ANNEX_PRIVATE_KEY = hexToBytes(
  '3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8',
);
export const ANNEX_PUBLIC_KEY = hexToBytes(
  '0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020' +
    'ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13',
);
export const ANNEX_NONCE = hexToBytes(
  '59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21',
);
export const ANNEX_SIGNATURE = Object.freeze({
  r: BigInt('0xf5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3'),
  s: BigInt('0xb1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa'),
});
export const ANNEX_CIPHERTEXT = Object.freeze({
  c1: hexToBytes(
    '0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73' +
      'e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0',
  ),
  c3: hexToBytes('59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766'),
  c2: hexToBytes('21886ca989ca9c7d58087307ca93092d651efa'),
});