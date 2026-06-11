import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-auth-callback',
  template: `
    <ion-content class="ion-padding ion-text-center">
      <ion-spinner name="crescent" style="margin-top:40vh"></ion-spinner>
      <p *ngIf="errorMsg" style="color:var(--ion-color-danger);margin-top:16px">{{ errorMsg }}</p>
    </ion-content>
  `,
  standalone: false,
})
export class AuthCallbackPage implements OnInit {
  errorMsg: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private auth: AuthService,
  ) {}

  async ngOnInit() {
    const code         = this.route.snapshot.queryParams['code'];
    const error        = this.route.snapshot.queryParams['error'];
    const returnedState = this.route.snapshot.queryParams['state'];

    if (error || !code) {
      await this.router.navigate(['/tabs/tab1'], { replaceUrl: true });
      return;
    }

    // CSRF: verify state matches what we stored before the redirect
    const expectedState = sessionStorage.getItem('pkce_state');
    sessionStorage.removeItem('pkce_state');
    if (!expectedState || returnedState !== expectedState) {
      console.error('[AuthCallback] state mismatch — possible CSRF attack');
      this.errorMsg = 'Error de seguridad. Redirigiendo...';
      setTimeout(() => this.router.navigate(['/tabs/tab1'], { replaceUrl: true }), 2000);
      return;
    }

    try {
      await this.auth.handleOidcCallback(code);
      await this.router.navigate(['/tabs/tab1'], { replaceUrl: true });
    } catch (e) {
      console.error('[AuthCallback] token exchange failed:', e);
      this.errorMsg = 'Error al completar el inicio de sesión. Redirigiendo...';
      setTimeout(() => this.router.navigate(['/tabs/tab1'], { replaceUrl: true }), 2000);
    }
  }
}
