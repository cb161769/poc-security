import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';
import { AuthService } from './auth.service';
import { CryptoService } from './crypto.service';

export interface JweResult<T = any> { jwe: string; data: T; }

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(
    private http: HttpClient,
    private auth: AuthService,
    private crypto: CryptoService
  ) {}

  private get base(): string {
    return this.auth.getChannel() === 'web'
      ? environment.webApiUrl
      : environment.mobileApiUrl;
  }

  private get headers(): HttpHeaders {
    return new HttpHeaders({
      Authorization: `Bearer ${this.auth.getToken()}`,
      'X-Client-Public-Key': this.crypto.getPublicKeyB64(),
    });
  }

  private async jweGet(path: string): Promise<JweResult> {
    const jwe = await firstValueFrom(
      this.http.get(`${this.base}${path}`, { headers: this.headers, responseType: 'text' })
    );
    return { jwe, data: await this.crypto.decryptJWE(jwe) };
  }

  private async jwePost(path: string, body: any, _retry = false): Promise<JweResult> {
    const isMobile = this.auth.getChannel() === 'mobile';
    await this.crypto.fetchServerPublicKey();

    let requestBody: any;
    let contentType: string;
    if (isMobile) {
      requestBody = await this.crypto.encryptForServer(body);
      contentType = 'application/jose';
    } else {
      requestBody = body;
      contentType = 'application/json';
    }

    const idempotencyKey = crypto.randomUUID();
    const headers = this.headers
      .set('X-Idempotency-Key', idempotencyKey)
      .set('Content-Type', contentType);

    try {
      const jwe = await firstValueFrom(
        this.http.post(`${this.base}${path}`, requestBody, { headers, responseType: 'text' })
      );
      return { jwe, data: await this.crypto.decryptJWE(jwe) };
    } catch (err: any) {
      if (!_retry && err?.status === 422 && err?.error?.error === 'KEY_ROTATED') {
        this.crypto.clearServerKey();
        return this.jwePost(path, body, true);
      }
      throw err;
    }
  }

  // ── api-node (Identity Bridge) ──────────────────────
  getProtectedData(): Promise<JweResult> {
    return this.jweGet('/api/v1/data');
  }

  // ── Transfers ────────────────────────────────────────
  getTransfers(): Promise<JweResult> {
    return this.jweGet('/transfers');
  }

  createTransfer(amount: number, to: string, memo: string): Promise<JweResult> {
    return this.jwePost('/transfers', { amount, to, memo });
  }

  // ── Payments ─────────────────────────────────────────
  getPayments(): Promise<JweResult> {
    return this.jweGet('/payments');
  }

  createPayment(amount: number, method: string, merchant: string): Promise<JweResult> {
    return this.jwePost('/payments', { amount, method, merchant });
  }
}
