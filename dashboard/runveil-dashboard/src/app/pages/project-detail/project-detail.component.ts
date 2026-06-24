import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { RunveilApiService, ScanView, TrendSummary, ComponentView } from '../../core/api/runveil-api.service';

type TrendBar = {
  at: string;
  total: number;
  reachable: number;
  segments: { cls: string; pct: number; label: string; count: number }[];
};

type ModalMode = 'ingest' | 'observe';

@Component({
  selector: 'rv-project-detail',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule],
  templateUrl: './project-detail.component.html',
})
export class ProjectDetailComponent {
  private route = inject(ActivatedRoute);
  private http = inject(HttpClient);
  private api = inject(RunveilApiService);

  slug = '';
  repoUrl: string | null = null;
  toast = '';

  // reachable/dormant overview
  total = 0;
  reachable = 0;
  dormant = 0;
  countsLoaded = false;

  // scan history
  scans: ScanView[] = [];
  scansLoaded = false;

  // trends (per-scan counts over time)
  trendBars: TrendBar[] = [];
  trendSummary: TrendSummary | null = null;
  trendsLoaded = false;

  // components (manifest-declared services)
  components: ComponentView[] = [];
  componentsLoaded = false;
  newComponentKey = '';
  newComponentName = '';
  newComponentKind = 'service';
  componentBusy = false;
  componentMsg = '';

  // Slack notifications
  slackWebhook = '';
  slackConfigured = false;
  slackBusy = false;
  slackMsg = '';

  // modal state
  modalOpen = false;
  mode: ModalMode = 'ingest';
  payloadText = '';
  runtimeToken = '';
  busy = false;
  error = '';

  ngOnInit() {
    this.slug = this.route.snapshot.paramMap.get('slug') || '';
    this.loadProject();
    this.loadCounts();
    this.loadScans();
    this.loadSettings();
    this.loadTrends();
    this.loadComponents();
  }

  loadComponents() {
    if (!this.slug) return;
    this.api.getComponents(this.slug).subscribe({
      next: (res) => {
        this.components = res.components ?? [];
        this.componentsLoaded = true;
      },
      error: () => {
        this.componentsLoaded = true;
      },
    });
  }

  createComponent() {
    const key = this.newComponentKey.trim().toLowerCase();
    if (!key) {
      this.componentMsg = 'Key is required.';
      return;
    }
    this.componentBusy = true;
    this.componentMsg = '';
    this.api
      .createComponent(this.slug, {
        key,
        name: this.newComponentName.trim(),
        kind: this.newComponentKind.trim() || 'service',
      })
      .subscribe({
        next: () => {
          this.componentBusy = false;
          this.newComponentKey = '';
          this.newComponentName = '';
          this.newComponentKind = 'service';
          this.componentMsg = '';
          this.loadComponents();
        },
        error: (e) => {
          this.componentBusy = false;
          this.componentMsg = e?.error?.error || `Failed to register component (${e?.status || 'unknown'})`;
        },
      });
  }

  severityClass(sev: string): string {
    switch ((sev || '').toUpperCase()) {
      case 'CRITICAL':
        return 'border-rose-500/30 bg-rose-500/10 text-rose-200';
      case 'HIGH':
        return 'border-orange-500/30 bg-orange-500/10 text-orange-200';
      case 'MEDIUM':
        return 'border-amber-400/30 bg-amber-400/10 text-amber-100';
      case 'LOW':
        return 'border-sky-400/20 bg-sky-400/10 text-sky-100';
      default:
        return 'border-white/10 bg-white/[0.03] text-slate-400';
    }
  }

  loadTrends() {
    if (!this.slug) return;
    this.api.getTrends(this.slug).subscribe({
      next: (res) => {
        const points = res.points ?? [];
        const max = Math.max(1, ...points.map((p) => p.total));
        this.trendBars = points.map((p) => ({
          at: p.at,
          total: p.total,
          reachable: p.reachable,
          segments: [
            { cls: 'bg-rose-500/80', pct: (p.critical / max) * 100, label: 'critical', count: p.critical },
            { cls: 'bg-orange-500/80', pct: (p.high / max) * 100, label: 'high', count: p.high },
            { cls: 'bg-amber-400/80', pct: (p.medium / max) * 100, label: 'medium', count: p.medium },
            { cls: 'bg-sky-400/70', pct: (p.low / max) * 100, label: 'low', count: p.low },
          ],
        }));
        this.trendSummary = res.summary;
        this.trendsLoaded = true;
      },
      error: () => {
        this.trendsLoaded = true;
      },
    });
  }

  loadScans() {
    if (!this.slug) return;
    this.api.getScans(this.slug).subscribe({
      next: (res) => {
        this.scans = res.scans ?? [];
        this.scansLoaded = true;
      },
      error: () => {
        this.scansLoaded = true;
      },
    });
  }

  loadProject() {
    if (!this.slug) return;
    this.api.getProject(this.slug).subscribe({
      next: (p) => { this.repoUrl = p.repo_url ?? null; },
      error: () => {},
    });
  }

  loadSettings() {
    if (!this.slug) return;
    this.http.get<any>(`/v1/projects/${this.slug}/settings`).subscribe({
      next: (res) => (this.slackConfigured = !!res?.slack_webhook_configured),
      error: () => {},
    });
  }

  saveSlack() {
    this.slackBusy = true;
    this.slackMsg = '';
    this.http
      .put<any>(`/v1/projects/${this.slug}/settings`, { slack_webhook_url: this.slackWebhook.trim() })
      .subscribe({
        next: (res) => {
          this.slackBusy = false;
          this.slackConfigured = !!res?.slack_webhook_configured;
          this.slackWebhook = '';
          this.slackMsg = this.slackConfigured ? 'Saved — alerts on new reachable risk are on.' : 'Slack alerts disabled.';
        },
        error: (e) => {
          this.slackBusy = false;
          this.slackMsg = e?.error?.error || 'Failed to save webhook.';
        },
      });
  }

  loadCounts() {
    if (!this.slug) return;
    this.api.getFindings(this.slug).subscribe({
      next: (res) => {
        const list = res.findings ?? [];
        this.total = list.length;
        this.reachable = list.filter((f) => f.reachable).length;
        this.dormant = this.total - this.reachable;
        this.countsLoaded = true;
      },
      error: () => {
        this.countsLoaded = true;
      },
    });
  }

  openIngest() {
    this.mode = 'ingest';
    this.error = '';
    this.busy = false;
    this.payloadText = this.sampleIngestPayload();
    this.modalOpen = true;
  }

  openObserve() {
    this.mode = 'observe';
    this.error = '';
    this.busy = false;
    this.payloadText = this.sampleObservePayload();
    this.modalOpen = true;
  }

  closeModal() {
    if (this.busy) return;
    this.modalOpen = false;
    this.error = '';
  }

  submit() {
    this.error = '';

    let body: any;
    try {
      body = JSON.parse(this.payloadText);
    } catch {
      this.error = 'Invalid JSON. Please fix and try again.';
      return;
    }

    this.busy = true;

    if (this.mode === 'ingest') {
      const url = `/v1/projects/${this.slug}/scans/ingest`;

      this.http.post<any>(url, body).subscribe({
        next: (res) => {
          this.busy = false;
          this.modalOpen = false;
          this.showToast(`Ingested ✅ scan_id=${res?.scan_id || 'ok'} (findings: ${res?.findings ?? '—'})`);
          this.loadCounts();
          this.loadScans();
          this.loadTrends();
          this.loadComponents();
        },
        error: (e) => {
          this.busy = false;
          this.error = e?.error?.error || e?.error?.details || `Ingest failed (${e?.status || 'unknown'})`;
        },
      });

      return;
    }

    // observe mode
    const token = (this.runtimeToken || '').trim();
    if (!token) {
      this.busy = false;
      this.error = 'Runtime token required. Paste it in "X-Runveil-Token".';
      return;
    }

    const url = `/v1/projects/${this.slug}/runtime/observe`;
    const headers = new HttpHeaders({ 'X-Runveil-Token': token });

    this.http.post<any>(url, body, { headers }).subscribe({
      next: (res) => {
        this.busy = false;
        this.modalOpen = false;
        this.showToast(`Runtime observed ✅ findings_updated=${res?.findings_updated ?? 'ok'}`);
        this.loadCounts();
      },
      error: (e) => {
        this.busy = false;
        this.error =
          e?.error?.error ||
          e?.error?.details ||
          `Observe failed (${e?.status || 'unknown'})`;
      },
    });
  }

  private sampleIngestPayload(): string {
    const now = new Date().toISOString();
    return JSON.stringify(
      {
        source: 'cli',
        report: {
          project_slug: this.slug || 'my-project',
          total: 2,
          max_severity: 'LOW',
          generated_at: now,
          findings: [
            {
              package: 'axios',
              version: '1.6.0',
              ecosystem: 'npm',
              vuln_id: 'CVE-2023-45857',
              summary: 'Server-Side Request Forgery in axios',
              severity: 'HIGH',
              reachable: true,
              dev: false,
              direct: true,
            },
            {
              package: 'minimist',
              version: '1.2.0',
              ecosystem: 'npm',
              vuln_id: 'GHSA-vh95-rmgr-6w4m',
              summary: 'Prototype Pollution in minimist (dev-only)',
              severity: 'MEDIUM',
              reachable: false,
              dev: true,
              direct: false,
            },
          ],
        },
      },
      null,
      2
    );
  }

  private sampleObservePayload(): string {
    return JSON.stringify(
      {
        environment: 'dev-local',
        packages: [{ name: 'lodash', version: '4.17.19' }],
      },
      null,
      2
    );
  }

  abs(n: number): number {
    return Math.abs(n);
  }

  private showToast(message: string) {
    this.toast = message;
    window.clearTimeout((this as any)._toastTimer);
    (this as any)._toastTimer = window.setTimeout(() => {
      this.toast = '';
    }, 3000);
  }
}
