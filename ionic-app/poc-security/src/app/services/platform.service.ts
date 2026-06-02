import { Injectable } from '@angular/core';
import { Capacitor } from '@capacitor/core';

export type Channel = 'web' | 'mobile';

@Injectable({ providedIn: 'root' })
export class PlatformService {
  getChannel(): Channel {
    return Capacitor.isNativePlatform() ? 'mobile' : 'web';
  }

  isMobile(): boolean {
    return this.getChannel() === 'mobile';
  }
}
