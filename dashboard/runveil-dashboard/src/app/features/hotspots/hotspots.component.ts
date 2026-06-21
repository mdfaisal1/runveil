import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { RunveilApiService, FindingView } from '../../core/api/runveil-api.service';

@Component({
  selector: 'app-hotspots',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './hotspots.component.html',
})
export class HotspotsComponent {
  private route = inject(ActivatedRoute);
  private api = inject(RunveilApiService);

  slug = signal<string>('');
  loading = signal<boolean>(true);
  error = signal<string>('');
  hotspots = signal<FindingView[]>([]);

  ngOnInit() {
    this.route.paramMap.subscribe((pm) => {
      this.slug.set(pm.get('slug') ?? '');
      this.load();
    });
  }

  load() {
    this.loading.set(true);
    this.error.set('');
    this.api.getHotspots(this.slug(), 20).subscribe({
      next: (res) => {
        this.hotspots.set(res.hotspots ?? []);
        this.loading.set(false);
      },
      error: (e) => {
        this.loading.set(false);
        this.error.set(e?.error?.error ?? e?.message ?? 'Failed to load hotspots');
      },
    });
  }

  badgeClass(sev: string) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'border-rose-500/30 bg-rose-500/10 text-rose-100';
    if (s === 'HIGH') return 'border-orange-500/30 bg-orange-500/10 text-orange-100';
    if (s === 'MEDIUM') return 'border-amber-400/30 bg-amber-400/10 text-amber-100';
    return 'border-sky-400/20 bg-sky-400/10 text-sky-100';
  }

  riskColor(score: number) {
    if (score >= 70) return 'bg-rose-500';
    if (score >= 40) return 'bg-orange-500';
    if (score >= 15) return 'bg-amber-400';
    return 'bg-slate-500';
  }
}
