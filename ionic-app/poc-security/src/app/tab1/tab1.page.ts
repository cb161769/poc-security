import { Component, OnInit } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { ApiService } from '../services/api.service';
import { CryptoService } from '../services/crypto.service';
import { PlatformService, Channel } from '../services/platform.service';

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
  channel: Channel = 'web';

  constructor(
    public auth: AuthService,
    private api: ApiService,
    private crypto: CryptoService,
    private platform: PlatformService
  ) {}

  async ngOnInit() {
    this.channel = this.platform.getChannel();
    await this.crypto.initialize(this.channel);
  }

  get channelLabel(): string {
    return this.channel === 'web' ? '🖥️ Web' : '📱 Mobile';
  }

  get channelColor(): string {
    return this.channel === 'web' ? 'tertiary' : 'success';
  }

  get jweStrategy(): string {
    return this.channel === 'web'
      ? 'Clave efímera no-extractable — forward secrecy por sesión'
      : 'Clave extractable — persistible en Secure Storage del dispositivo';
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
