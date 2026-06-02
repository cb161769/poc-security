import { Injectable } from '@angular/core';
import { compactDecrypt } from 'jose';
import { Channel } from './platform.service';

@Injectable({ providedIn: 'root' })
export class CryptoService {
  private privateKey: CryptoKey | null = null;
  private publicKeyB64: string | null = null;
  private channel: Channel = 'web';

  async initialize(channel: Channel): Promise<void> {
    this.channel = channel;
    channel === 'web' ? await this.initWeb() : await this.initMobile();
  }

  /**
   * Web — clave efímera no-extractable.
   * Forward secrecy por sesión: la clave muere cuando cierra la pestaña.
   * XSS no puede exportar la private key fuera del contexto WebCrypto.
   */
  private async initWeb(): Promise<void> {
    // Paso 1: generar par extractable para poder exportar ambas claves
    const tempPair = await window.crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );

    // Paso 2: exportar la clave pública (se envía al servidor)
    const pubJwk = await window.crypto.subtle.exportKey('jwk', tempPair.publicKey);
    this.publicKeyB64 = btoa(JSON.stringify(pubJwk));

    // Paso 3: exportar clave privada temporalmente y re-importar como no-extractable
    const privJwk = await window.crypto.subtle.exportKey('jwk', tempPair.privateKey);

    this.privateKey = await window.crypto.subtle.importKey(
      'jwk',
      privJwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,       // ← no-extractable: XSS no puede robarla con exportKey()
      ['decrypt']
    );

    // Paso 4: limpiar la JWK temporal de memoria (best-effort)
    Object.keys(privJwk).forEach(k => { (privJwk as any)[k] = null; });
  }

  /**
   * Mobile — clave extractable con Capacitor.
   * Puede persistirse en el Secure Storage del dispositivo (Keychain/Keystore).
   * En esta POC se mantiene en memoria; en producción usar @capacitor/preferences
   * con valores cifrados por el hardware del dispositivo.
   */
  private async initMobile(): Promise<void> {
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,        // ← extractable: se puede persistir en Secure Storage
      ['encrypt', 'decrypt']
    );

    this.privateKey = keyPair.privateKey;
    const pubJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    this.publicKeyB64 = btoa(JSON.stringify(pubJwk));

    // TODO producción:
    // const privJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
    // await Preferences.set({ key: 'rsa_priv', value: JSON.stringify(privJwk) });
  }

  getPublicKeyB64(): string {
    if (!this.publicKeyB64) throw new Error('CryptoService sin inicializar');
    return this.publicKeyB64;
  }

  getChannel(): Channel {
    return this.channel;
  }

  async decryptJWE(jweToken: string): Promise<any> {
    if (!this.privateKey) throw new Error('CryptoService sin inicializar');
    const { plaintext } = await compactDecrypt(jweToken, this.privateKey);
    return JSON.parse(new TextDecoder().decode(plaintext));
  }
}
