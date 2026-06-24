import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map } from 'rxjs/operators';
import { of } from 'rxjs';
import { AuthService } from './auth.service';

// Allows navigation only when a session exists. Uses the cached user when known,
// otherwise probes /v1/auth/me. Redirects to /login (preserving returnUrl) if not.
export const authGuard: CanActivateFn = (_route, state) => {
    const auth = inject(AuthService);
    const router = inject(Router);

    const allowOrRedirect = (ok: boolean) =>
        ok ? true : router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });

    if (auth.loaded() && auth.isAuthenticated()) {
        return true;
    }
    if (auth.loaded() && !auth.isAuthenticated()) {
        return of(allowOrRedirect(false));
    }
    return auth.refresh().pipe(map((u) => allowOrRedirect(u !== null)));
};
