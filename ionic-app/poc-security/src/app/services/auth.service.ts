import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';
import { Channel, PlatformService } from './platform.service';

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private token: string | null = null;
  private channel: Channel;
  private expiresAt: number | null = null; // ms epoch

  constructor(private http: HttpClient, private platform: PlatformService) {
    this.channel = this.platform.getChannel();
  }

  private get realmConfig() {
    return this.channel === 'web'
      ? { tokenUrl: `${environment.webKeycloakUrl}/protocol/openid-connect/token`, clientId: environment.webKeycloakClientId }
      : { tokenUrl: `${environment.keycloakUrl}/protocol/openid-connect/token`,    clientId: environment.keycloakClientId };
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

    this.token = resp.access_token;

    // Extraer exp del JWT payload (base64url, parte 2)
    try {
      const payload = JSON.parse(atob(resp.access_token.split('.')[1]));
      this.expiresAt = payload.exp * 1000;
    } catch {
      this.expiresAt = Date.now() + resp.expires_in * 1000;
    }
  }

  getToken(): string | null      { return this.token; }
  getChannel(): Channel          { return this.channel; }
  isLoggedIn(): boolean          { return !!this.token; }
  getExpiresAt(): number | null  { return this.expiresAt; }

  getSecondsRemaining(): number {
    if (!this.expiresAt) return 0;
    return Math.max(0, Math.floor((this.expiresAt - Date.now()) / 1000));
  }

  isExpired(): boolean {
    return !!this.expiresAt && Date.now() >= this.expiresAt;
  }

  logout(): void {
    this.token = null;
    this.expiresAt = null;
  }
}
