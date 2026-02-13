import { CommonModule } from '@angular/common';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, HostListener, inject } from '@angular/core';
import { ReactiveFormsModule, FormBuilder, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';

interface Project {
  slug: string;
  name: string;
  updated_at?: string;
}

@Component({
  selector: 'app-projects',
  standalone: true,
  imports: [CommonModule, RouterLink, ReactiveFormsModule],
  templateUrl: './projects.component.html',
})
export class ProjectsComponent {
  private http = inject(HttpClient);
  private router = inject(Router);
  private fb = inject(FormBuilder);

  projects: Project[] = [];
  loading = true;
  error: string | null = null;

  showCreate = false;
  createError: string | null = null;
  slugTouched = false;

  createForm = this.fb.group({
    name: ['', [Validators.required, Validators.minLength(2)]],
    slug: ['', [Validators.required, Validators.pattern(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)]],
    repoUrl: [''],
  });

  constructor() {
    this.fetchProjects();
  }

  fetchProjects() {
    this.loading = true;
    this.error = null;

    this.http.get<any>('/v1/projects').subscribe({
      next: (res) => {
        const list: Project[] = Array.isArray(res) ? res : (res?.projects ?? []);
        this.projects = list ?? [];
        this.loading = false;
      },
      error: (err: HttpErrorResponse) => {
        this.loading = false;
        this.error = err?.error?.error || err.message || 'Failed to load projects';
      },
    });
  }

  openCreate() {
    this.showCreate = true;
    this.createError = null;
    this.slugTouched = false;

    // keep current values, just clear errors
    this.createForm.markAsPristine();
    this.createForm.markAsUntouched();
  }

  closeCreate() {
    this.showCreate = false;
    this.createError = null;
  }

  onNameInput() {
    if (this.slugTouched) return;

    const name = (this.createForm.value.name ?? '').toString();
    const slug = this.slugify(name);
    this.createForm.patchValue({ slug }, { emitEvent: false });
  }

  onSlugInput() {
    this.slugTouched = true;
    const slug = (this.createForm.value.slug ?? '').toString();
    this.createForm.patchValue({ slug: this.slugify(slug) }, { emitEvent: false });
  }

  private slugify(v: string) {
    return v
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }

  createProject() {
    this.createError = null;

    if (this.createForm.invalid) {
      this.createForm.markAllAsTouched();
      return;
    }

    const name = (this.createForm.value.name ?? '').toString().trim();
    const slug = (this.createForm.value.slug ?? '').toString().trim();
    const repoUrl = (this.createForm.value.repoUrl ?? '').toString().trim();

    const payload: any = { name, slug };
    if (repoUrl) payload.repo_url = repoUrl;

    this.http.post('/v1/projects', payload).subscribe({
      next: () => {
        this.showCreate = false;
        this.createForm.reset({ name: '', slug: '', repoUrl: '' });
        this.slugTouched = false;
        this.fetchProjects();
      },
      error: (err: HttpErrorResponse) => {
        if (err.status === 404) {
          this.createError =
            'Create API not found (POST /v1/projects). Add the POST route in your Go API.';
          return;
        }
        this.createError = err?.error?.error || err.message || 'Failed to create project';
      },
    });
  }

  openProject(slug: string) {
    this.router.navigate(['/projects', slug]);
  }

  trackBySlug = (_: number, p: Project) => p.slug;

  @HostListener('document:keydown.escape')
  onEsc() {
    if (this.showCreate) this.closeCreate();
  }
}
