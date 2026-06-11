import { Injectable } from '@angular/core';
import { Preferences } from '@capacitor/preferences';

// NOTE: @capacitor/preferences uses unencrypted SharedPreferences on Android.
// Production should replace this with EncryptedSharedPreferences via a native plugin
// (addresses MASVS-STORAGE-1 / Ph.17 warning in the Android security test report).
@Injectable({ providedIn: 'root' })
export class SecureStorageService {
  private readonly RT_KEY = 'keystone_rt';

  async storeRefreshToken(token: string): Promise<void> {
    await Preferences.set({ key: this.RT_KEY, value: token });
  }

  async loadRefreshToken(): Promise<string | null> {
    const { value } = await Preferences.get({ key: this.RT_KEY });
    return value;
  }

  async clearRefreshToken(): Promise<void> {
    await Preferences.remove({ key: this.RT_KEY });
  }
}
