import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';

// A single finding as returned by GET /v1/projects/:slug/findings.
interface Finding {
    package: string;
    version: string;
    ecosystem: string;
    vuln_id: string;
    summary: string;
    severity: string;
    reachable: boolean;
    runtime_state?: string;
    risk_score?: number;
}

interface FindingsResponse {
    project_slug: string;
    findings: Finding[] | null;
}

function cfg() {
    const c = vscode.workspace.getConfiguration('runveil');
    return {
        apiBase: (c.get<string>('apiBase') || 'http://localhost:8080').replace(/\/+$/, ''),
        token: c.get<string>('token') || '',
        project: c.get<string>('project') || '',
    };
}

// Minimal JSON GET with a Bearer token (read endpoints are org-scoped).
function getJSON<T>(urlStr: string, token: string): Promise<T> {
    return new Promise((resolve, reject) => {
        const u = new URL(urlStr);
        const lib = u.protocol === 'https:' ? https : http;
        const req = lib.request(
            u,
            {
                method: 'GET',
                headers: token ? { Authorization: `Bearer ${token}` } : {},
            },
            (res) => {
                let body = '';
                res.on('data', (chunk) => (body += chunk));
                res.on('end', () => {
                    const status = res.statusCode ?? 0;
                    if (status === 401) {
                        return reject(new Error('Unauthorized — set a read-scoped key in runveil.token.'));
                    }
                    if (status === 404) {
                        return reject(new Error('Project not found (check runveil.project / your org).'));
                    }
                    if (status < 200 || status >= 300) {
                        return reject(new Error(`API returned ${status}`));
                    }
                    try {
                        resolve(JSON.parse(body) as T);
                    } catch (e) {
                        reject(new Error('Invalid JSON from API'));
                    }
                });
            }
        );
        req.on('error', reject);
        req.end();
    });
}

class FindingNode extends vscode.TreeItem {
    constructor(public readonly finding: Finding) {
        const reach = finding.reachable ? '🔥 reachable' : '💤 dormant';
        super(`${finding.package}@${finding.version}`, vscode.TreeItemCollapsibleState.None);
        this.description = `${finding.severity} · ${reach}`;
        this.tooltip = `${finding.vuln_id}\n${finding.summary}\nrisk: ${finding.risk_score ?? '—'}`;
        this.contextValue = 'runveilFinding';
    }
}

class FindingsProvider implements vscode.TreeDataProvider<FindingNode> {
    private _onDidChange = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChange.event;

    private items: FindingNode[] = [];
    private message = 'Run "Runveil: Refresh Findings".';

    refresh(): void {
        this.load().then(() => this._onDidChange.fire());
    }

    getTreeItem(e: FindingNode): vscode.TreeItem {
        return e;
    }

    getChildren(): vscode.ProviderResult<FindingNode[]> {
        if (this.items.length === 0) {
            const placeholder = new vscode.TreeItem(this.message);
            return [placeholder as FindingNode];
        }
        return this.items;
    }

    private async load(): Promise<void> {
        const { apiBase, token, project } = cfg();
        if (!project) {
            this.items = [];
            this.message = 'Set runveil.project (Runveil: Configure).';
            return;
        }
        try {
            const res = await getJSON<FindingsResponse>(
                `${apiBase}/v1/projects/${encodeURIComponent(project)}/findings`,
                token
            );
            const findings = res.findings ?? [];
            // Reachable first, then by severity rank — mirrors the CLI/dashboard.
            const rank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
            findings.sort((a, b) => {
                if (a.reachable !== b.reachable) return a.reachable ? -1 : 1;
                return (rank[b.severity?.toUpperCase()] ?? 0) - (rank[a.severity?.toUpperCase()] ?? 0);
            });
            this.items = findings.map((f) => new FindingNode(f));
            this.message = `No findings for "${project}".`;
        } catch (err: any) {
            this.items = [];
            this.message = err?.message ?? 'Failed to load findings.';
            vscode.window.showErrorMessage(`Runveil: ${this.message}`);
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    const provider = new FindingsProvider();
    context.subscriptions.push(
        vscode.window.registerTreeDataProvider('runveil.findings', provider),
        vscode.commands.registerCommand('runveil.refreshFindings', () => provider.refresh()),
        vscode.commands.registerCommand('runveil.setup', async () => {
            const c = vscode.workspace.getConfiguration('runveil');
            const project = await vscode.window.showInputBox({
                prompt: 'Runveil project slug',
                value: c.get<string>('project') || '',
            });
            if (project !== undefined) {
                await c.update('project', project, vscode.ConfigurationTarget.Global);
            }
            const token = await vscode.window.showInputBox({
                prompt: 'Runveil read-scoped API key (rv_...)',
                password: true,
                value: c.get<string>('token') || '',
            });
            if (token !== undefined) {
                await c.update('token', token, vscode.ConfigurationTarget.Global);
            }
            provider.refresh();
        })
    );
    provider.refresh();
}

export function deactivate() {}
