import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription, interval } from 'rxjs';
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
export class Tab1Page implements OnInit, OnDestroy {
  username = '';
  password = '';
  loading = false;
  error: string | null = null;
  data: any = null;
  rawJwe: string | null = null;
  channel: Channel = 'web';

  // Timer
  timeRemaining = '';
  private timerSub: Subscription | null = null;

  constructor(
    public auth: AuthService,
    private api: ApiService,
    private crypto: CryptoService,
    private platform: PlatformService
  ) {}

  async ngOnInit() {
    this.channel = this.platform.getChannel();
    await this.crypto.initialize(this.channel);
    this.timerSub = interval(1000).subscribe(() => this.updateTimer());
  }

  ngOnDestroy() {
    this.timerSub?.unsubscribe();
  }

  private updateTimer() {
    if (!this.auth.isLoggedIn()) { this.timeRemaining = ''; return; }
    const secs = this.auth.getSecondsRemaining();
    if (secs <= 0) { this.timeRemaining = 'Expirada'; return; }
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    this.timeRemaining = `${m}:${s.toString().padStart(2, '0')}`;
  }

  get timerColor(): string {
    const secs = this.auth.getSecondsRemaining();
    if (secs <= 0)  return 'danger';
    if (secs <= 30) return 'danger';
    if (secs <= 60) return 'warning';
    return 'success';
  }

  get channelLabel(): string { return this.channel === 'web' ? '🖥️ Web' : '📱 Mobile'; }
  get channelColor(): string { return this.channel === 'web' ? 'tertiary' : 'success'; }

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
      this.updateTimer();
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
    this.timeRemaining = '';
  }
}
