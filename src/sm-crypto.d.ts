declare module 'sm-crypto' {
  type ByteInput = string | number[] | Uint8Array;

  interface SignatureOptions {
    der?: boolean;
    hash?: boolean;
    publicKey?: string;
    userId?: string;
  }

  interface Sm2Reference {
    doEncrypt(message: ByteInput, publicKey: string, cipherMode?: 0 | 1): string;
    doDecrypt(
      ciphertext: string,
      privateKey: string,
      cipherMode?: 0 | 1,
      options?: { output?: 'string' | 'array' },
    ): string | number[];
    doSignature(message: ByteInput, privateKey: string, options?: SignatureOptions): string;
    doVerifySignature(
      message: ByteInput,
      signature: string,
      publicKey: string,
      options?: SignatureOptions,
    ): boolean;
    getPublicKeyFromPrivateKey(privateKey: string): string;
  }

  export const sm2: Sm2Reference;
}