import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';

// Sends the session cookie on every request and bounces to /login on a 401.
// (Same-origin via the dev proxy, but withCredentials keeps it correct if the
// API is ever served cross-origin.)
export const authInterceptor: HttpInterceptorFn = (req, next) => {
    const router = inject(Router);
    const authReq = req.clone({ withCredentials: true });

    return next(authReq).pipe(
        catchError((err) => {
            const onAuthRoute = req.url.includes('/v1/auth/');
            if (err?.status === 401 && !onAuthRoute) {
                router.navigate(['/login'], { queryParams: { returnUrl: router.url } });
            }
            return throwError(() => err);
        })
    );
};
