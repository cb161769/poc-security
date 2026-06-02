import { Component, OnDestroy, OnInit } from '@angular/core';
import { AlertController } from '@ionic/angular';
import { Subscription, interval } from 'rxjs';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  templateUrl: 'app.component.html',
  styleUrls: ['app.component.scss'],
  standalone: false,
})
export class AppComponent implements OnInit, OnDestroy {
  private watchSub: Subscription | null = null;
  private warningShown = false;
  private expiredShown = false;

  constructor(private auth: AuthService, private alertCtrl: AlertController) {}

  ngOnInit() {
    // Vigilar expiración cada segundo
    this.watchSub = interval(1000).subscribe(() => this.checkExpiry());
  }

  ngOnDestroy() {
    this.watchSub?.unsubscribe();
  }

  private async checkExpiry() {
    if (!this.auth.isLoggedIn()) {
      // Resetear flags cuando no hay sesión (para el próximo login)
      this.warningShown = false;
      this.expiredShown = false;
      return;
    }

    const secs = this.auth.getSecondsRemaining();

    // Alerta de aviso a los 30 segundos
    if (secs <= 30 && secs > 0 && !this.warningShown) {
      this.warningShown = true;
      const alert = await this.alertCtrl.create({
        header: '⚠️ Sesión por vencer',
        message: `Tu sesión expirará en <strong>${secs} segundos</strong>.<br>Guarda tu trabajo.`,
        buttons: ['Entendido'],
        backdropDismiss: true,
      });
      await alert.present();
    }

    // Alerta de sesión expirada
    if (secs === 0 && !this.expiredShown) {
      this.expiredShown = true;
      this.auth.logout();
      const alert = await this.alertCtrl.create({
        header: '🔒 Sesión expirada',
        message: 'Tu sesión JWT ha expirado. Inicia sesión nuevamente para continuar.',
        buttons: [{ text: 'Ir a Login', role: 'confirm' }],
        backdropDismiss: false,
      });
      await alert.present();
    }
  }
}
