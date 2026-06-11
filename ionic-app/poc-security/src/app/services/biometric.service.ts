import { Injectable } from '@angular/core';
import { BiometricAuth, BiometryError } from '@aparajita/capacitor-biometric-auth';

@Injectable({ providedIn: 'root' })
export class BiometricService {

  async isAvailable(): Promise<boolean> {
    try {
      const result = await BiometricAuth.checkBiometry();
      return result.isAvailable;
    } catch {
      return false;
    }
  }

  async authenticate(reason: string): Promise<boolean> {
    try {
      await BiometricAuth.authenticate({
        reason,
        cancelTitle: 'Usar contraseña',
        allowDeviceCredential: false,
      });
      return true;
    } catch (e) {
      if (e instanceof BiometryError) {
        console.warn('[BiometricService] auth cancelled/failed:', e.code, e.message);
      }
      return false;
    }
  }
}
