import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';
import { Channel, PlatformService } from './platform.service';
import { CryptoService } from './crypto.service';

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token?: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private token: string | null = null;
  private refreshToken: string | null = null;
  private channel: Channel;
  private expiresAt: number | null = null; // ms epoch

  constructor(private http: HttpClient, private platform: PlatformService, private crypto: CryptoService) {
    this.channel = this.platform.getChannel();
  }

  get realmConfig() {
    return this.channel === 'web'
      ? { tokenUrl: `${environment.webKeycloakUrl}/protocol/openid-connect/token`, clientId: environment.webKeycloakClientId }
      : { tokenUrl: `${environment.keycloakUrl}/protocol/openid-connect/token`,    clientId: environment.keycloakClientId };
  }

  private applyTokenResponse(resp: TokenResponse): void {
    this.token = resp.access_token;
    this.refreshToken = resp.refresh_token ?? null;
    try {
      const payload = JSON.parse(atob(resp.access_token.split('.')[1]));
      this.expiresAt = payload.exp * 1000;
    } catch {
      this.expiresAt = Date.now() + resp.expires_in * 1000;
    }
  }

  async login(username: string, password: string): Promise<void> {
    const { tokenUrl, clientId } = this.realmConfig;
    const body = new URLSearchParams({ client_id: clientId, grant_type: 'password', username, password });

    const resp = await firstValueFrom(
      this.http.post<TokenResponse>(
        tokenUrl,
        body.toString(),
        { headers: new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }) }
      )
    );
    this.applyTokenResponse(resp);
  }

  async loginWithRefreshToken(rt: string): Promise<void> {
    const { tokenUrl, clientId } = this.realmConfig;
    const body = new URLSearchParams({
      client_id:     clientId,
      grant_type:    'refresh_token',
      refresh_token: rt,
    });

    const resp = await firstValueFrom(
      this.http.post<TokenResponse>(
        tokenUrl,
        body.toString(),
        { headers: new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }) }
      )
    );
    this.applyTokenResponse(resp);
  }

  async handleOidcCallback(code: string): Promise<void> {
    const verifier = sessionStorage.getItem('pkce_verifier');
    if (!verifier) throw new Error('No PKCE verifier in session');
    sessionStorage.removeItem('pkce_verifier');

    const { tokenUrl, clientId } = this.realmConfig;
    const body = new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     clientId,
      code,
      redirect_uri:  `${window.location.origin}/auth/callback`,
      code_verifier: verifier,
    });

    const resp = await firstValueFrom(
      this.http.post<TokenResponse>(
        tokenUrl,
        body.toString(),
        { headers: new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }) }
      )
    );
    this.applyTokenResponse(resp);
  }

  async initiatePasskeyLogin(): Promise<void> {
    const verifier = this.generateCodeVerifier();
    const challenge = await this.generateCodeChallenge(verifier);
    const state = this.generateCodeVerifier(); // cryptographically random state

    sessionStorage.setItem('pkce_verifier', verifier);
    sessionStorage.setItem('pkce_state', state);

    const { tokenUrl, clientId } = this.realmConfig;
    const authUrl = tokenUrl.replace('/protocol/openid-connect/token', '/protocol/openid-connect/auth');

    const params = new URLSearchParams({
      client_id:             clientId,
      redirect_uri:          `${window.location.origin}/auth/callback`,
      response_type:         'code',
      scope:                 'openid',
      code_challenge:        challenge,
      code_challenge_method: 'S256',
      acr_values:            'webauthn-passwordless',
      state,
    });
    window.location.href = `${authUrl}?${params}`;
  }

  private generateCodeVerifier(): string {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode(...arr))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private async generateCodeChallenge(verifier: string): Promise<string> {
    const data = new TextEncoder().encode(verifier);
    const digest = await crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  getToken(): string | null         { return this.token; }
  getRefreshToken(): string | null  { return this.refreshToken; }
  getChannel(): Channel             { return this.channel; }
  isLoggedIn(): boolean             { return !!this.token; }
  getExpiresAt(): number | null     { return this.expiresAt; }

  getSecondsRemaining(): number {
    if (!this.expiresAt) return 0;
    return Math.max(0, Math.floor((this.expiresAt - Date.now()) / 1000));
  }

  isExpired(): boolean {
    return !!this.expiresAt && Date.now() >= this.expiresAt;
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const apiBase = this.channel === 'web'
      ? environment.webApiUrl
      : environment.mobileApiUrl;
    await firstValueFrom(
      this.http.post(
        `${apiBase}/change-password`,
        { currentPassword, newPassword },
        { headers: new HttpHeaders({
            Authorization: `Bearer ${this.token}`,
            'Content-Type': 'application/json',
          })
        }
      )
    );
  }

  logout(): void {
    this.token = null;
    this.refreshToken = null;
    this.expiresAt = null;
    this.crypto.clearKey();
  }
}
