import { Routes } from '@angular/router';
import { ShellComponent } from './layout/shell/shell.component';
import { ProjectsComponent } from './pages/projects/projects.component';
import { authGuard } from './core/auth/auth.guard';

export const routes: Routes = [
    {
        path: 'login',
        loadComponent: () =>
            import('./features/login/login.component').then((m) => m.LoginComponent),
    },
    {
        path: '',
        component: ShellComponent,
        canActivate: [authGuard],
        children: [
            { path: '', pathMatch: 'full', redirectTo: 'projects' },

            { path: 'projects', component: ProjectsComponent },

            {
                path: 'members',
                loadComponent: () =>
                    import('./features/members/members.component').then((m) => m.MembersComponent),
            },

            // ✅ Findings page (wired to /v1/projects/:slug/findings via RunveilApiService)
            {
                path: 'projects/:slug/findings',
                loadComponent: () =>
                    import('./features/findings/findings.component').then((m) => m.FindingsComponent),
            },

            // Finding detail + evidence explorer
            {
                path: 'projects/:slug/findings/:id',
                loadComponent: () =>
                    import('./features/finding-detail/finding-detail.component').then((m) => m.FindingDetailComponent),
            },

            // Hotspots (risk-ranked findings)
            {
                path: 'projects/:slug/hotspots',
                loadComponent: () =>
                    import('./features/hotspots/hotspots.component').then((m) => m.HotspotsComponent),
            },

            // Project detail (keep as lazy-load so it works even if your component isn't standalone yet)
            {
                path: 'projects/:slug',
                loadComponent: () =>
                    import('./pages/project-detail/project-detail.component').then((m) => m.ProjectDetailComponent),
            },
        ],
    },

    // ✅ wildcard MUST be last
    { path: '**', redirectTo: 'projects' },
];
