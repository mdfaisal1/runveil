import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export type Project = {
    id?: string;
    slug: string;
    name: string;
    repo_url?: string | null;
    created_at?: string;
    updated_at?: string;
};

@Injectable({ providedIn: 'root' })
export class ApiService {
    constructor(private http: HttpClient) { }

    health(): Observable<{ ok: boolean }> {
        return this.http.get<{ ok: boolean }>('/health');
    }

    listProjects(): Observable<Project[]> {
        return this.http.get<any>('/v1/projects').pipe(
            map((res) => {
                if (Array.isArray(res)) return res;
                if (res?.items && Array.isArray(res.items)) return res.items;
                if (res?.projects && Array.isArray(res.projects)) return res.projects;
                return [];
            })
        );
    }
}
