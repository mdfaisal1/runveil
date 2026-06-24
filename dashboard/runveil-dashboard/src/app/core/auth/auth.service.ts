import { Injectable, computed, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';

export type Membership = {
    org_id: string;
    slug: string;
    name: string;
    role: string;
};

export type CurrentUser = {
    user_id: string;
    email: string;
    name: string;
    org_id: string;
    org_slug: string;
    org_name: string;
    role: string;
    orgs: Membership[];
};

@Injectable({ providedIn: 'root' })
export class AuthService {
    private http = inject(HttpClient);

    // Null = unknown/loading, undefined-via-signal handled by `loaded`.
    readonly user = signal<CurrentUser | null>(null);
    readonly loaded = signal<boolean>(false);
    readonly isAuthenticated = computed(() => this.user() !== null);

    /** Fetch the current session user; resolves to null when unauthenticated. */
    refresh(): Observable<CurrentUser | null> {
        return new Observable<CurrentUser | null>((sub) => {
            this.http.get<CurrentUser>('/v1/auth/me').subscribe({
                next: (u) => {
                    this.user.set(u);
                    this.loaded.set(true);
                    sub.next(u);
                    sub.complete();
                },
                error: () => {
                    this.user.set(null);
                    this.loaded.set(true);
                    sub.next(null);
                    sub.complete();
                },
            });
        });
    }

    login(email: string, password: string): Observable<any> {
        return this.http
            .post('/v1/auth/login', { email, password })
            .pipe(tap(() => this.refresh().subscribe()));
    }

    signup(body: { email: string; password: string; name?: string; org_name?: string }): Observable<any> {
        return this.http
            .post('/v1/auth/signup', body)
            .pipe(tap(() => this.refresh().subscribe()));
    }

    logout(): Observable<any> {
        return this.http.post('/v1/auth/logout', {}).pipe(
            tap(() => {
                this.user.set(null);
                this.loaded.set(true);
            })
        );
    }

    switchOrg(orgId: string): Observable<any> {
        return this.http
            .post('/v1/auth/switch-org', { org_id: orgId })
            .pipe(tap(() => this.refresh().subscribe()));
    }

    /** Resolve whether an email's domain has SSO; returns an IdP auth URL if so. */
    oidcStart(email: string): Observable<{ sso: boolean; auth_url?: string }> {
        return this.http.post<{ sso: boolean; auth_url?: string }>('/v1/auth/oidc/start', { email });
    }
}
