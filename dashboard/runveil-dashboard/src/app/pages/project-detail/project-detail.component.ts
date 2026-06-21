import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { RunveilApiService } from '../../core/api/runveil-api.service';

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
  toast = '';

  // reachable/dormant overview
  total = 0;
  reachable = 0;
  dormant = 0;
  countsLoaded = false;

  // modal state
  modalOpen = false;
  mode: ModalMode = 'ingest';
  payloadText = '';
  runtimeToken = '';
  busy = false;
  error = '';

  ngOnInit() {
    this.slug = this.route.snapshot.paramMap.get('slug') || '';
    this.loadCounts();
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

  private showToast(message: string) {
    this.toast = message;
    window.clearTimeout((this as any)._toastTimer);
    (this as any)._toastTimer = window.setTimeout(() => {
      this.toast = '';
    }, 3000);
  }
}
