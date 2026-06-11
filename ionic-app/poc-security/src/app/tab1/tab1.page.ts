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

  timeRemaining = '';
  private timerSub: Subscription | null = null;

  private loginAttempts = 0;
  private lockoutUntil = 0;

  // Change password
  showChangePwd = false;
  currentPwd = '';
  newPwd = '';
  confirmPwd = '';
  changePwdLoading = false;
  changePwdError: string | null = null;
  changePwdSuccess = false;

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

  get lockoutSecondsRemaining(): number {
    return Math.max(0, Math.ceil((this.lockoutUntil - Date.now()) / 1000));
  }

  async login() {
    if (Date.now() < this.lockoutUntil) {
      this.error = `Demasiados intentos. Espera ${this.lockoutSecondsRemaining}s`;
      return;
    }
    if (!this.username.trim() || !this.password) {
      this.error = 'Completa todos los campos';
      return;
    }
    this.loading = true;
    this.error = null;
    try {
      await this.auth.login(this.username.trim(), this.password);
      this.loginAttempts = 0;
      this.updateTimer();
    } catch {
      this.loginAttempts++;
      if (this.loginAttempts >= 5) {
        this.lockoutUntil = Date.now() + 60_000;
        this.error = 'Demasiados intentos. Espera 60 segundos.';
      } else {
        this.error = 'Credenciales incorrectas';
      }
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

  toggleChangePwd() {
    this.showChangePwd = !this.showChangePwd;
    this.currentPwd = '';
    this.newPwd = '';
    this.confirmPwd = '';
    this.changePwdError = null;
    this.changePwdSuccess = false;
  }

  private validateChangePwd(): string | null {
    if (!this.currentPwd) return 'Ingresa tu contraseña actual';
    if (!this.newPwd || this.newPwd.length < 8) return 'La nueva contraseña debe tener al menos 8 caracteres';
    if (this.newPwd === this.currentPwd) return 'La nueva contraseña debe ser diferente a la actual';
    if (this.newPwd !== this.confirmPwd) return 'Las contraseñas no coinciden';
    return null;
  }

  async changePassword() {
    const err = this.validateChangePwd();
    if (err) { this.changePwdError = err; return; }

    this.changePwdLoading = true;
    this.changePwdError = null;
    this.changePwdSuccess = false;
    try {
      await this.auth.changePassword(this.currentPwd, this.newPwd);
      this.changePwdSuccess = true;
      this.currentPwd = '';
      this.newPwd = '';
      this.confirmPwd = '';
    } catch (e: any) {
      if (e?.status === 400) this.changePwdError = e?.error?.error ?? 'Contraseña actual incorrecta';
      else if (e?.status === 401) this.changePwdError = 'Sesión expirada, vuelve a iniciar sesión';
      else if (e?.status === 403) this.changePwdError = 'No tienes permiso para cambiar la contraseña';
      else this.changePwdError = 'Error al cambiar la contraseña, intenta nuevamente';
    } finally {
      this.changePwdLoading = false;
    }
  }

  logout() {
    this.auth.logout();
    this.data = null;
    this.rawJwe = null;
    this.error = null;
    this.timeRemaining = '';
    this.loginAttempts = 0;
    this.lockoutUntil = 0;
    this.showChangePwd = false;
  }
}
