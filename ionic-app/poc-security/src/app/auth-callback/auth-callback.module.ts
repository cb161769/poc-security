import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { IonicModule } from '@ionic/angular';
import { AuthCallbackPage } from './auth-callback.page';

const routes: Routes = [{ path: '', component: AuthCallbackPage }];

@NgModule({
  declarations: [AuthCallbackPage],
  imports: [CommonModule, IonicModule, RouterModule.forChild(routes)],
})
export class AuthCallbackModule {}
