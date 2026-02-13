import { Routes } from '@angular/router';
import { ShellComponent } from './layout/shell/shell.component';
import { ProjectsComponent } from './pages/projects/projects.component';
import { ProjectDetailComponent } from './pages/project-detail/project-detail.component';

export const routes: Routes = [
    {
        path: '',
        component: ShellComponent,
        children: [
            { path: '', pathMatch: 'full', redirectTo: 'projects' },
            { path: 'projects', component: ProjectsComponent },
            { path: 'projects/:slug', component: ProjectDetailComponent },
        ],
    },
    { path: '**', redirectTo: 'projects' },
    {
        path: 'projects/:slug/findings',
        loadComponent: () =>
            import('./features/findings/findings.component').then((m) => m.FindingsComponent),
    },
];
