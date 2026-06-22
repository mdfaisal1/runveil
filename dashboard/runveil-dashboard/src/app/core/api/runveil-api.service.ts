import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export type FindingView = {
    id: string;
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
    risk_score?: number;
};

export type FindingsResponse = {
    project_slug: string;
    findings: FindingView[];
};

export type HotspotsResponse = {
    project_slug: string;
    hotspots: FindingView[];
};

export type FindingDetail = {
    id: string;
    package: string;
    version: string;
    ecosystem: string;
    vuln_id: string;
    summary: string;
    severity: string;
    reachable: boolean;
    is_dev?: boolean;
    is_direct?: boolean;
    fixed_version?: string;
    introduced_via?: string;
    evidence_count: number;
    first_seen_at?: string | null;
    last_seen_at?: string | null;
    runtime_state?: string;
};

export type EvidenceEvent = {
    occurred_at: string;
    environment?: string;
    package_name: string;
    package_version: string;
};

export type EvidenceResponse = {
    finding: FindingDetail;
    evidence: EvidenceEvent[];
};

export type ProjectSummary = {
    slug: string;
    name: string;
    repo_url?: string | null;
    updated_at?: string;
};

export type ScanView = {
    id: string;
    status: string;
    source?: string | null;
    lockfile_path?: string | null;
    package_count: number;
    finding_count: number;
    started_at: string;
    finished_at?: string | null;
};

export type ScansResponse = {
    project_slug: string;
    scans: ScanView[];
};

@Injectable({ providedIn: 'root' })
export class RunveilApiService {
    private http = inject(HttpClient);

    getProject(slug: string): Observable<ProjectSummary> {
        return this.http.get<ProjectSummary>(`/v1/projects/${slug}`);
    }

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

    getFindingEvidence(
        slug: string,
        id: string,
        opts?: { environment?: string }
    ): Observable<EvidenceResponse> {
        let params = new HttpParams();
        if (opts?.environment) params = params.set('environment', opts.environment);
        return this.http.get<EvidenceResponse>(
            `/v1/projects/${slug}/findings/${id}/evidence`,
            { params }
        );
    }

    getHotspots(slug: string, limit = 20): Observable<HotspotsResponse> {
        const params = new HttpParams().set('limit', String(limit));
        return this.http.get<HotspotsResponse>(`/v1/projects/${slug}/hotspots`, { params });
    }

    getScans(slug: string): Observable<ScansResponse> {
        return this.http.get<ScansResponse>(`/v1/projects/${slug}/scans`);
    }
}
