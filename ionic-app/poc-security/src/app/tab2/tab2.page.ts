import { Component } from '@angular/core';
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

  // Formulario
  amount: number | null = null;
  to = '';
  memo = '';
  formResult: any = null;

  constructor(public auth: AuthService, private api: ApiService) {}

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
      this.error = e?.error?.error ?? e?.message ?? 'Error al cargar transferencias';
    } finally {
      this.loading = false;
    }
  }

  async submit() {
    if (this.amount == null || this.amount <= 0 || !this.to) {
      this.error = 'Cantidad inválida o destinatario vacío';
      return;
    }
    this.sending = true;
    this.error = null;
    this.formResult = null;
    try {
      // removed accidental debugger; keep logic lean for production
      const { jwe, data } = await this.api.createTransfer(this.amount, this.to, this.memo);
      this.lastJwe = jwe;
      this.formResult = data.transfer;
      this.transfers = [data.transfer, ...this.transfers];
      this.amount = null; this.to = ''; this.memo = '';
    } catch (e: any) {
      this.error = e?.error?.error ?? e?.message ?? 'Error al crear transferencia';
    } finally {
      this.sending = false;
    }
  }

  statusColor(s: string) {
    return s === 'completed' ? 'success' : s === 'pending' ? 'warning' : 'danger';
  }
}
