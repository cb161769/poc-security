import { Injectable } from '@angular/core';
import { compactDecrypt } from 'jose';

@Injectable({ providedIn: 'root' })
export class CryptoService {
  private privateKey: CryptoKey | null = null;
  private publicKeyB64: string | null = null;

  async initialize(): Promise<void> {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );

    this.privateKey = keyPair.privateKey;
    const pubJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    this.publicKeyB64 = btoa(JSON.stringify(pubJwk));
  }

  getPublicKeyB64(): string {
    if (!this.publicKeyB64) throw new Error('CryptoService sin inicializar');
    return this.publicKeyB64;
  }

  async decryptJWE(jweToken: string): Promise<any> {
    if (!this.privateKey) throw new Error('CryptoService sin inicializar');
    const { plaintext } = await compactDecrypt(jweToken, this.privateKey);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
}
