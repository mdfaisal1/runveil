import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
    selector: 'app-login',
    standalone: true,
    imports: [CommonModule, FormsModule],
    templateUrl: './login.component.html',
})
export class LoginComponent {
    private auth = inject(AuthService);
    private router = inject(Router);
    private route = inject(ActivatedRoute);

    mode = signal<'login' | 'signup'>('login');
    email = '';
    password = '';
    name = '';
    orgName = '';
    busy = signal(false);
    error = signal('');

    toggleMode() {
        this.mode.set(this.mode() === 'login' ? 'signup' : 'login');
        this.error.set('');
    }

    continueWithSso() {
        const email = this.email.trim();
        if (!email) {
            this.error.set('Enter your work email to continue with SSO.');
            return;
        }
        this.busy.set(true);
        this.error.set('');
        this.auth.oidcStart(email).subscribe({
            next: (res) => {
                if (res.sso && res.auth_url) {
                    window.location.href = res.auth_url; // hand off to the IdP
                } else {
                    this.busy.set(false);
                    this.error.set('No SSO is configured for that email domain. Use your password.');
                }
            },
            error: (e) => {
                this.busy.set(false);
                this.error.set(e?.error?.error || 'Could not start SSO.');
            },
        });
    }

    submit() {
        this.error.set('');
        this.busy.set(true);
        const done = {
            next: () => {
                this.busy.set(false);
                const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') || '/projects';
                this.router.navigateByUrl(returnUrl);
            },
            error: (e: any) => {
                this.busy.set(false);
                this.error.set(e?.error?.error || 'Something went wrong. Please try again.');
            },
        };

        if (this.mode() === 'login') {
            this.auth.login(this.email.trim(), this.password).subscribe(done);
        } else {
            this.auth
                .signup({
                    email: this.email.trim(),
                    password: this.password,
                    name: this.name.trim(),
                    org_name: this.orgName.trim(),
                })
                .subscribe(done);
        }
    }
}
