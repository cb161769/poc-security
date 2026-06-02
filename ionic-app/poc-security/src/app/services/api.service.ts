import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';
import { AuthService } from './auth.service';
import { CryptoService } from './crypto.service';

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(
    private http: HttpClient,
    private auth: AuthService,
    private crypto: CryptoService
  ) {}

  private get apiBase(): string {
    return this.auth.getChannel() === 'web'
      ? environment.webApiUrl
      : environment.mobileApiUrl;
  }

  async getProtectedData(): Promise<{ jwe: string; data: any }> {
    const jwe = await firstValueFrom(
      this.http.get(`${this.apiBase}/api/v1/data`, {
        headers: new HttpHeaders({
          Authorization: `Bearer ${this.auth.getToken()}`,
          'X-Client-Public-Key': this.crypto.getPublicKeyB64(),
        }),
        responseType: 'text',
      })
    );

    const data = await this.crypto.decryptJWE(jwe);
    return { jwe, data };
  }
}
