import { Component } from '@angular/core';
import { AlertController } from '@ionic/angular';
import { AuthService } from '../services/auth.service';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-tab3',
  templateUrl: 'tab3.page.html',
  styleUrls: ['tab3.page.scss'],
  standalone: false,
})
export class Tab3Page {
  payments: any[] = [];
  loading = false;
  sending = false;
  error: string | null = null;
  lastJwe: string | null = null;

  amount: number | null = null;
  method = 'card';
  merchant = '';
  formResult: any = null;

  constructor(
    public auth: AuthService,
    private api: ApiService,
    private alertCtrl: AlertController
  ) {}

  get channelColor() { return this.auth.getChannel() === 'web' ? 'tertiary' : 'success'; }

  async loadPayments() {
    if (!this.auth.isLoggedIn()) return;
    this.loading = true;
    this.error = null;
    try {
      const { jwe, data } = await this.api.getPayments();
      this.payments = data.data ?? [];
      this.lastJwe = jwe;
    } catch (e: any) {
      this.error = this.mapError(e);
    } finally {
      this.loading = false;
    }
  }

  private validatePayment(): string | null {
    if (this.amount == null || this.amount <= 0 || this.amount > 5000)
      return 'Monto debe ser entre $0.01 y $5,000';
    if (!['card', 'ach', 'wire'].includes(this.method))
      return 'Método de pago inválido';
    if (!this.merchant || this.merchant.trim().length < 2)
      return 'Ingresa el nombre del comercio';
    return null;
  }

  private mapError(e: any): string {
    if (e?.status === 422) return 'Datos inválidos, verifica los campos';
    if (e?.status === 403) return 'No autorizado para esta operación';
    if (e?.status >= 500) return 'Error del servidor, intenta nuevamente';
    return 'Operación fallida';
  }

  async submit() {
    const validationError = this.validatePayment();
    if (validationError) { this.error = validationError; return; }

    const confirmed = await this.confirmPayment();
    if (!confirmed) return;

    await this.doPayment();
  }

  private async confirmPayment(): Promise<boolean> {
    const methodLabel: Record<string, string> = { card: 'Tarjeta', ach: 'ACH', wire: 'Wire' };
    return new Promise(async resolve => {
      const alert = await this.alertCtrl.create({
        header: 'Confirmar pago',
        message: `¿Pagar <strong>${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(this.amount!)}</strong> a <strong>${this.merchant.trim()}</strong> via ${methodLabel[this.method] ?? this.method}?`,
        buttons: [
          { text: 'Cancelar', role: 'cancel', handler: () => resolve(false) },
          { text: 'Confirmar', handler: () => resolve(true) },
        ],
      });
      await alert.present();
    });
  }

  private async doPayment() {
    this.sending = true;
    this.error = null;
    this.formResult = null;
    try {
      const { jwe, data } = await this.api.createPayment(this.amount!, this.method, this.merchant.trim());
      this.lastJwe = jwe;
      this.formResult = data.payment;
      this.payments = [data.payment, ...this.payments];
      this.amount = null; this.merchant = '';
    } catch (e: any) {
      this.error = this.mapError(e);
    } finally {
      this.sending = false;
    }
  }

  statusColor(s: string) {
    return s === 'settled' ? 'success' : s === 'processing' ? 'warning' : 'danger';
  }

  methodIcon(m: string) {
    return m === 'card' ? 'card-outline' : 'swap-horizontal-outline';
  }
}
