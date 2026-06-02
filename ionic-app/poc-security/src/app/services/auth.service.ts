import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';
import { environment } from '../../environments/environment';

interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private token: string | null = null;

  constructor(private http: HttpClient) {}

  async login(username: string, password: string): Promise<void> {
    const body = new URLSearchParams({
      client_id: environment.keycloakClientId,
      grant_type: 'password',
      username,
      password,
    });

    const resp = await firstValueFrom(
      this.http.post<TokenResponse>(
        `${environment.keycloakUrl}/protocol/openid-connect/token`,
        body.toString(),
        { headers: new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }) }
      )
    );

    this.token = resp.access_token;
  }

  getToken(): string | null {
    return this.token;
  }

  isLoggedIn(): boolean {
    return !!this.token;
  }

  logout(): void {
    this.token = null;
  }
}
