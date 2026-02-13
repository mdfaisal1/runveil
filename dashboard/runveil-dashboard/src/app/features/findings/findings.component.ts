import { CommonModule } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { RunveilApiService, FindingView } from '../../core/api/runveil-api.service';

type ReachableFilter = 'all' | 'reachable' | 'dormant';

@Component({
  selector: 'app-findings',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './findings.component.html',
})
export class FindingsComponent {
  private route = inject(ActivatedRoute);
  private api = inject(RunveilApiService);

  slug = signal<string>('');
  loading = signal<boolean>(true);
  error = signal<string>('');

  reachableFilter = signal<ReachableFilter>('all');
  search = signal<string>('');
  severity = signal<'all' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('all');

  findings = signal<FindingView[]>([]);

  counts = computed(() => {
    const list = this.findings();
    const reachable = list.filter((x) => x.reachable).length;
    const dormant = list.length - reachable;
    return { total: list.length, reachable, dormant };
  });

  filtered = computed(() => {
    const q = this.search().trim().toLowerCase();
    const sev = this.severity();
    const rf = this.reachableFilter();

    return this.findings().filter((f) => {
      if (rf === 'reachable' && !f.reachable) return false;
      if (rf === 'dormant' && f.reachable) return false;

      if (sev !== 'all' && (f.severity || '').toUpperCase() !== sev) return false;

      if (!q) return true;
      const hay = `${f.package} ${f.vuln_id} ${f.summary} ${f.ecosystem} ${f.version}`.toLowerCase();
      return hay.includes(q);
    });
  });

  ngOnInit() {
    this.route.paramMap.subscribe((pm) => {
      const slug = pm.get('slug') ?? '';
      this.slug.set(slug);
      this.load();
    });
  }

  load() {
    this.loading.set(true);
    this.error.set('');

    this.api.getFindings(this.slug()).subscribe({
      next: (res) => {
        this.findings.set(res.findings ?? []);
        this.loading.set(false);
      },
      error: (e) => {
        this.loading.set(false);
        this.error.set(e?.message ?? 'Failed to load findings');
      },
    });
  }

  setReachable(v: ReachableFilter) {
    this.reachableFilter.set(v);
  }

  badgeClass(sev: string) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'border-rose-500/30 bg-rose-500/10 text-rose-100';
    if (s === 'HIGH') return 'border-orange-500/30 bg-orange-500/10 text-orange-100';
    if (s === 'MEDIUM') return 'border-amber-400/30 bg-amber-400/10 text-amber-100';
    return 'border-sky-400/20 bg-sky-400/10 text-sky-100';
  }

  runtimeBadgeClass(reachable: boolean) {
    return reachable
      ? 'border-orange-500/25 bg-orange-500/10 text-orange-100'
      : 'border-white/10 bg-white/[0.03] text-slate-300';
  }
}
