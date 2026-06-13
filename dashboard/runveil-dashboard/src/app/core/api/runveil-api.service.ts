import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export type FindingView = {
    package: string;
    version: string;
    ecosystem: string;
    vuln_id: string;
    summary: string;
    severity: string;
    reachable: boolean;
    is_dev?: boolean; // dev-only dependency (why a finding is dormant)
    is_direct?: boolean; // direct dependency of the project
    evidence_count: number;
    last_seen_at?: string | null;
    runtime_state?: string; // backend sends this in your code
};

export type FindingsResponse = {
    project_slug: string;
    findings: FindingView[];
};

@Injectable({ providedIn: 'root' })
export class RunveilApiService {
    private http = inject(HttpClient);

    getFindings(
        slug: string,
        opts?: { reachable?: 'true' | 'false'; hasEvidence?: 'true' | 'false' }
    ): Observable<FindingsResponse> {
        let params = new HttpParams();
        if (opts?.reachable) params = params.set('reachable', opts.reachable);
        if (opts?.hasEvidence) params = params.set('has_evidence', opts.hasEvidence);

        // IMPORTANT: use relative URL so your proxy keeps working
        return this.http.get<FindingsResponse>(`/v1/projects/${slug}/findings`, { params });
    }
}
