import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RunveilApiService, AuditEntry } from '../../core/api/runveil-api.service';

@Component({
    selector: 'app-audit',
    standalone: true,
    imports: [CommonModule],
    templateUrl: './audit.component.html',
})
export class AuditComponent implements OnInit {
    private api = inject(RunveilApiService);

    entries = signal<AuditEntry[]>([]);
    loading = signal(true);
    error = signal('');

    ngOnInit() {
        this.api.getAudit(200).subscribe({
            next: (res) => {
                this.entries.set(res.entries ?? []);
                this.loading.set(false);
            },
            error: (e) => {
                this.loading.set(false);
                this.error.set(
                    e?.status === 403
                        ? 'Audit log is visible to admins and owners only.'
                        : e?.error?.error ?? 'Failed to load audit log'
                );
            },
        });
    }

    actionClass(action: string): string {
        if (action.endsWith('login_failed')) return 'border-rose-500/30 bg-rose-500/10 text-rose-200';
        if (action.startsWith('auth.')) return 'border-sky-400/30 bg-sky-400/10 text-sky-100';
        if (action.startsWith('member.') || action.startsWith('sso.'))
            return 'border-orange-500/30 bg-orange-500/10 text-orange-200';
        return 'border-white/10 bg-white/[0.03] text-slate-300';
    }

    metaText(m?: Record<string, any>): string {
        if (!m) return '';
        return Object.entries(m)
            .map(([k, v]) => `${k}=${v}`)
            .join(' · ');
    }
}
