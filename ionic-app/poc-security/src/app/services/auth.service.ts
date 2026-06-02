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
  }

  getToken(): string | null { return this.token; }
  getChannel(): Channel     { return this.channel; }
  isLoggedIn(): boolean     { return !!this.token; }
  logout(): void            { this.token = null; }
}
