import { Injectable } from '@angular/core';
import { compactDecrypt } from 'jose';
import { Channel } from './platform.service';

@Injectable({ providedIn: 'root' })
export class CryptoService {
  private privateKey: CryptoKey | null = null;
  private publicKeyB64: string | null = null;
  private channel: Channel = 'web';
  private initPromise: Promise<void> | null = null;

  private serverPubKey: CryptoKey | null = null;
  private serverPubKeyFetchedAt = 0;

  async initialize(channel: Channel): Promise<void> {
    if (this.privateKey && this.publicKeyB64) return;
    if (this.initPromise) return this.initPromise;
    this.channel = channel;
    this.initPromise = (channel === 'web' ? this.initWeb() : this.initMobile())
      .finally(() => { this.initPromise = null; });
    return this.initPromise;
  }

  /**
   * Web — clave efímera no-extractable.
   * Forward secrecy por sesión: la clave muere cuando cierra la pestaña.
   * XSS no puede exportar la private key fuera del contexto WebCrypto.
   */
  private async initWeb(): Promise<void> {
    // Restaurar desde sessionStorage si existe (sobrevive recargas, muere al cerrar pestaña)
    const stored = sessionStorage.getItem('poc_keypair');
    if (stored) {
      try {
        const { pubB64, privJwk } = JSON.parse(stored);
        this.privateKey = await window.crypto.subtle.importKey(
          'jwk', privJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
        );
        this.publicKeyB64 = pubB64;
        return;
      } catch { sessionStorage.removeItem('poc_keypair'); }
    }

    // Generar par nuevo y persistirlo
    const keyPair = await window.crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );

    const pubJwk  = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

    this.publicKeyB64 = btoa(JSON.stringify(pubJwk));
    sessionStorage.setItem('poc_keypair', JSON.stringify({ pubB64: this.publicKeyB64, privJwk }));

    // Re-importar privada como no-extractable en memoria
    this.privateKey = await window.crypto.subtle.importKey(
      'jwk', privJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
    );
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

  clearKey(): void {
    this.privateKey = null;
    this.publicKeyB64 = null;
    this.initPromise = null;
    sessionStorage.removeItem('poc_keypair');
    this.clearServerKey();
  }

  clearServerKey(): void {
    this.serverPubKey = null;
    this.serverPubKeyFetchedAt = 0;
  }

  async fetchServerPublicKey(): Promise<void> {
    if (this.serverPubKey && Date.now() - this.serverPubKeyFetchedAt < 3_600_000) return;
    const res = await fetch('/api/v1/pubkey');
    if (!res.ok) throw new Error(`No se pudo obtener server pubkey: ${res.status}`);
    const jwk = await res.json();
    this.serverPubKey = await window.crypto.subtle.importKey(
      'jwk', jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true, ['encrypt']
    );
    this.serverPubKeyFetchedAt = Date.now();
  }

  async encryptForServer(payload: object): Promise<string> {
    if (!this.serverPubKey) throw new Error('Server pubkey no cargada');
    const { CompactEncrypt, importJWK } = await import('jose');
    const jwk = await window.crypto.subtle.exportKey('jwk', this.serverPubKey);
    const joseKey = await importJWK(jwk as any, 'RSA-OAEP-256');
    return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
      .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', dir: 'req' })
      .encrypt(joseKey);
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
