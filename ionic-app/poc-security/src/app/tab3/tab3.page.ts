import { Component } from '@angular/core';
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

  constructor(public auth: AuthService, private api: ApiService) {}

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
      this.error = e?.error?.error ?? e?.message ?? 'Error al cargar pagos';
    } finally {
      this.loading = false;
    }
  }

  async submit() {
    if (!this.amount || !this.merchant) return;
    this.sending = true;
    this.error = null;
    this.formResult = null;
    try {
      const { jwe, data } = await this.api.createPayment(this.amount, this.method, this.merchant);
      this.lastJwe = jwe;
      this.formResult = data.payment;
      this.payments = [data.payment, ...this.payments];
      this.amount = null; this.merchant = '';
    } catch (e: any) {
      this.error = e?.error?.error ?? e?.message ?? 'Error al crear pago';
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
