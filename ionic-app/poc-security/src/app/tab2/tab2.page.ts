import { Component } from '@angular/core';
import { AlertController } from '@ionic/angular';
import { AuthService } from '../services/auth.service';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-tab2',
  templateUrl: 'tab2.page.html',
  styleUrls: ['tab2.page.scss'],
  standalone: false,
})
export class Tab2Page {
  transfers: any[] = [];
  loading = false;
  sending = false;
  error: string | null = null;
  lastJwe: string | null = null;

  amount: number | null = null;
  to = '';
  memo = '';
  formResult: any = null;

  constructor(
    public auth: AuthService,
    private api: ApiService,
    private alertCtrl: AlertController
  ) {}

  get channelColor() { return this.auth.getChannel() === 'web' ? 'tertiary' : 'success'; }

  async loadTransfers() {
    if (!this.auth.isLoggedIn()) return;
    this.loading = true;
    this.error = null;
    try {
      const { jwe, data } = await this.api.getTransfers();
      this.transfers = data.data ?? [];
      this.lastJwe = jwe;
    } catch (e: any) {
      this.error = this.mapError(e);
    } finally {
      this.loading = false;
    }
  }

  private validateTransfer(): string | null {
    if (this.amount == null || this.amount <= 0 || this.amount > 10000)
      return 'Monto debe ser entre $0.01 y $10,000';
    if (!/^\d+(\.\d{1,2})?$/.test(String(this.amount)))
      return 'Monto inválido (máximo 2 decimales)';
    if (!/^ACC-[A-Z0-9]{4,8}$/.test(this.to.trim()))
      return 'Cuenta destino inválida (formato ACC-XXXX)';
    if (this.memo.length > 255)
      return 'Descripción máximo 255 caracteres';
    return null;
  }

  private mapError(e: any): string {
    if (e?.status === 422) return 'Datos inválidos, verifica los campos';
    if (e?.status === 403) return 'No autorizado para esta operación';
    if (e?.status >= 500) return 'Error del servidor, intenta nuevamente';
    return 'Operación fallida';
  }

  async submit() {
    const validationError = this.validateTransfer();
    if (validationError) { this.error = validationError; return; }

    const confirmed = await this.confirmTransfer();
    if (!confirmed) return;

    await this.doTransfer();
  }

  private async confirmTransfer(): Promise<boolean> {
    return new Promise(async resolve => {
      const alert = await this.alertCtrl.create({
        header: 'Confirmar transferencia',
        message: `¿Transferir <strong>${new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(this.amount!)}</strong> a <strong>${this.to.trim()}</strong>?`,
        buttons: [
          { text: 'Cancelar', role: 'cancel', handler: () => resolve(false) },
          { text: 'Confirmar', handler: () => resolve(true) },
        ],
      });
      await alert.present();
    });
  }

  private async doTransfer() {
    this.sending = true;
    this.error = null;
    this.formResult = null;
    try {
      const { jwe, data } = await this.api.createTransfer(this.amount!, this.to.trim(), this.memo.trim());
      this.lastJwe = jwe;
      this.formResult = data.transfer;
      this.transfers = [data.transfer, ...this.transfers];
      this.amount = null; this.to = ''; this.memo = '';
    } catch (e: any) {
      this.error = this.mapError(e);
    } finally {
      this.sending = false;
    }
  }

  statusColor(s: string) {
    return s === 'completed' ? 'success' : s === 'pending' ? 'warning' : 'danger';
  }
}
