import { Component, OnDestroy, OnInit } from '@angular/core';
import { AlertController } from '@ionic/angular';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  templateUrl: 'app.component.html',
  styleUrls: ['app.component.scss'],
  standalone: false,
})
export class AppComponent implements OnInit, OnDestroy {
  private warnTimer: ReturnType<typeof setTimeout> | null = null;
  private expireTimer: ReturnType<typeof setTimeout> | null = null;
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private auth: AuthService, private alertCtrl: AlertController) {}

  ngOnInit() {
    // Poll for login events at low frequency; timers are rescheduled on each login
    this.pollForLogin();
  }

  ngOnDestroy() {
    this.clearTimers();
  }

  private clearTimers() {
    if (this.warnTimer)   { clearTimeout(this.warnTimer);   this.warnTimer   = null; }
    if (this.expireTimer) { clearTimeout(this.expireTimer); this.expireTimer = null; }
    if (this.pollTimer)   { clearTimeout(this.pollTimer);   this.pollTimer   = null; }
  }

  private pollForLogin() {
    if (this.auth.isLoggedIn() && !this.expireTimer) {
      this.scheduleExpiryTimers();
    }
    this.pollTimer = setTimeout(() => this.pollForLogin(), 2000);
  }

  scheduleExpiryTimers() {
    this.clearTimers();
    const expiresAt = this.auth.getExpiresAt();
    if (!expiresAt) return;

    const msUntilExpiry = expiresAt - Date.now();
    if (msUntilExpiry <= 0) { this.onExpired(); return; }

    const msUntilWarning = msUntilExpiry - 30_000;
    if (msUntilWarning > 0) {
      this.warnTimer = setTimeout(() => this.onWarning(), msUntilWarning);
    }
    this.expireTimer = setTimeout(() => this.onExpired(), msUntilExpiry);

    this.pollTimer = setTimeout(() => this.pollForLogin(), 2000);
  }

  private async onWarning() {
    if (!this.auth.isLoggedIn()) return;
    const secs = this.auth.getSecondsRemaining();
    const alert = await this.alertCtrl.create({
      header: '⚠️ Sesión por vencer',
      message: `Tu sesión expirará en <strong>${secs} segundos</strong>.<br>Guarda tu trabajo.`,
      buttons: ['Entendido'],
      backdropDismiss: true,
    });
    await alert.present();
  }

  private async onExpired() {
    if (!this.auth.isLoggedIn()) return;
    this.auth.logout();
    this.clearTimers();
    const alert = await this.alertCtrl.create({
      header: '🔒 Sesión expirada',
      message: 'Tu sesión JWT ha expirado. Inicia sesión nuevamente para continuar.',
      buttons: [{ text: 'Ir a Login', role: 'confirm' }],
      backdropDismiss: false,
    });
    await alert.present();
  }
}
