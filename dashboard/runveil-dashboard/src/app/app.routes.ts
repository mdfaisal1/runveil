import { Routes } from '@angular/router';
import { ShellComponent } from './layout/shell/shell.component';
import { ProjectsComponent } from './pages/projects/projects.component';

export const routes: Routes = [
    {
        path: '',
        component: ShellComponent,
        children: [
            { path: '', pathMatch: 'full', redirectTo: 'projects' },

            { path: 'projects', component: ProjectsComponent },

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
