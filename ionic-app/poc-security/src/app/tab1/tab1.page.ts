import { Component, OnInit } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { ApiService } from '../services/api.service';
import { CryptoService } from '../services/crypto.service';

@Component({
  selector: 'app-tab1',
  templateUrl: 'tab1.page.html',
  styleUrls: ['tab1.page.scss'],
  standalone: false,
})
export class Tab1Page implements OnInit {
  username = '';
  password = '';
  loading = false;
  error: string | null = null;
  data: any = null;
  rawJwe: string | null = null;

  constructor(
    public auth: AuthService,
    private api: ApiService,
    private crypto: CryptoService
  ) {}

  async ngOnInit() {
    await this.crypto.initialize();
  }

  async login() {
    this.loading = true;
    this.error = null;
    try {
      await this.auth.login(this.username, this.password);
    } catch {
      this.error = 'Credenciales inválidas';
    } finally {
      this.loading = false;
    }
  }

  async loadData() {
    this.loading = true;
    this.error = null;
    this.data = null;
    this.rawJwe = null;
    try {
      const result = await this.api.getProtectedData();
      this.rawJwe = result.jwe;
      this.data = result.data;
    } catch (e: any) {
      this.error = e?.error?.error || e?.message || 'Error al cargar datos';
    } finally {
      this.loading = false;
    }
  }

  logout() {
    this.auth.logout();
    this.data = null;
    this.rawJwe = null;
    this.error = null;
  }
}
