import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterModule } from '@angular/router';
import {
  RunveilApiService,
  FindingDetail,
  EvidenceEvent,
} from '../../core/api/runveil-api.service';

@Component({
  selector: 'app-finding-detail',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './finding-detail.component.html',
})
export class FindingDetailComponent {
  private route = inject(ActivatedRoute);
  private api = inject(RunveilApiService);

  slug = signal<string>('');
  id = signal<string>('');
  loading = signal<boolean>(true);
  error = signal<string>('');

  finding = signal<FindingDetail | null>(null);
  evidence = signal<EvidenceEvent[]>([]);

  // Group evidence into per-day buckets for a simple timeline chart.
  timeline = computed(() => {
    const byDay = new Map<string, number>();
    for (const e of this.evidence()) {
      const day = (e.occurred_at || '').slice(0, 10);
      if (day) byDay.set(day, (byDay.get(day) ?? 0) + 1);
    }
    const days = [...byDay.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const max = days.reduce((m, [, c]) => Math.max(m, c), 1);
    return days.map(([day, count]) => ({ day, count, pct: Math.round((count / max) * 100) }));
  });

  ngOnInit() {
    this.route.paramMap.subscribe((pm) => {
      this.slug.set(pm.get('slug') ?? '');
      this.id.set(pm.get('id') ?? '');
      this.load();
    });
  }

  load() {
    this.loading.set(true);
    this.error.set('');
    this.api.getFindingEvidence(this.slug(), this.id()).subscribe({
      next: (res) => {
        this.finding.set(res.finding);
        this.evidence.set(res.evidence ?? []);
        this.loading.set(false);
      },
      error: (e) => {
        this.loading.set(false);
        this.error.set(e?.error?.error ?? e?.message ?? 'Failed to load finding');
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

  reachLabel() {
    const f = this.finding();
    if (!f) return '';
    if (f.reachable) return 'Reachable';
    return f.is_dev ? 'Dormant · dev-only' : 'Dormant';
  }
}
