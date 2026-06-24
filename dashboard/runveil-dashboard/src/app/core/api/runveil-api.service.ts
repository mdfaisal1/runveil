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

export type TrendPoint = {
    scan_id: string;
    at: string;
    total: number;
    reachable: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
};

export type TrendSummary = {
    scans: number;
    latest_total: number;
    previous_total: number;
    delta_total: number;
    latest_reachable: number;
    delta_reachable: number;
};

export type TrendsResponse = {
    project_slug: string;
    points: TrendPoint[];
    summary: TrendSummary;
};

export type ComponentView = {
    key: string;
    name: string;
    kind: string;
    created_at: string;
    finding_count: number;
    reachable_count: number;
    max_severity: string; // "" when no findings yet
    last_scanned_at?: string | null;
};

export type ComponentsResponse = {
    project_slug: string;
    components: ComponentView[];
};

export type OrgMember = {
    user_id: string;
    email: string;
    name: string;
    role: string;
    joined_at: string;
};

export type PendingInvite = {
    email: string;
    role: string;
    created_at: string;
    expires_at: string;
};

export type MembersResponse = {
    members: OrgMember[];
    pending_invites: PendingInvite[];
};

export type AuditEntry = {
    actor: string;
    action: string;
    target?: string;
    metadata?: Record<string, any>;
    ip?: string;
    at: string;
};

@Injectable({ providedIn: 'root' })
export class RunveilApiService {
    private http = inject(HttpClient);

    getProject(slug: string): Observable<ProjectSummary> {
        return this.http.get<ProjectSummary>(`/v1/projects/${slug}`);
    }

    getFindings(
        slug: string,
        opts?: { reachable?: 'true' | 'false'; hasEvidence?: 'true' | 'false'; component?: string }
    ): Observable<FindingsResponse> {
        let params = new HttpParams();
        if (opts?.reachable) params = params.set('reachable', opts.reachable);
        if (opts?.hasEvidence) params = params.set('has_evidence', opts.hasEvidence);
        if (opts?.component) params = params.set('component', opts.component);

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

    getTrends(slug: string, opts?: { limit?: number; component?: string }): Observable<TrendsResponse> {
        let params = new HttpParams().set('limit', String(opts?.limit ?? 60));
        if (opts?.component) params = params.set('component', opts.component);
        return this.http.get<TrendsResponse>(`/v1/projects/${slug}/trends`, { params });
    }

    getComponents(slug: string): Observable<ComponentsResponse> {
        return this.http.get<ComponentsResponse>(`/v1/projects/${slug}/components`);
    }

    createComponent(
        slug: string,
        body: { key: string; name?: string; kind?: string }
    ): Observable<ComponentView> {
        return this.http.post<ComponentView>(`/v1/projects/${slug}/components`, body);
    }

    // ---- org members (RBAC) ----
    getMembers(): Observable<MembersResponse> {
        return this.http.get<MembersResponse>('/v1/org/members');
    }

    addMember(email: string, role: string): Observable<any> {
        return this.http.post('/v1/org/members', { email, role });
    }

    changeMemberRole(userId: string, role: string): Observable<any> {
        return this.http.patch(`/v1/org/members/${userId}`, { role });
    }

    removeMember(userId: string): Observable<any> {
        return this.http.delete(`/v1/org/members/${userId}`);
    }

    // ---- audit log ----
    getAudit(limit = 100): Observable<{ entries: AuditEntry[] }> {
        return this.http.get<{ entries: AuditEntry[] }>(`/v1/org/audit?limit=${limit}`);
    }

    // ---- org SSO (OIDC) ----
    getOidcConfig(): Observable<any> {
        return this.http.get('/v1/org/oidc');
    }

    putOidcConfig(body: {
        domain: string;
        issuer: string;
        client_id: string;
        client_secret: string;
        default_role?: string;
    }): Observable<any> {
        return this.http.put('/v1/org/oidc', body);
    }
}
