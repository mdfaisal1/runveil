import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
    RunveilApiService,
    OrgMember,
    PendingInvite,
} from '../../core/api/runveil-api.service';
import { AuthService } from '../../core/auth/auth.service';

const ROLE_RANK: Record<string, number> = { viewer: 1, member: 2, admin: 3, owner: 4 };

@Component({
    selector: 'app-members',
    standalone: true,
    imports: [CommonModule, FormsModule],
    templateUrl: './members.component.html',
})
export class MembersComponent implements OnInit {
    private api = inject(RunveilApiService);
    private auth = inject(AuthService);

    members = signal<OrgMember[]>([]);
    invites = signal<PendingInvite[]>([]);
    loading = signal(true);
    error = signal('');
    msg = signal('');

    inviteEmail = '';
    inviteRole = 'member';
    busy = signal(false);

    roles = ['viewer', 'member', 'admin', 'owner'];

    // Current user's role decides which controls show.
    myRole = computed(() => this.auth.user()?.role ?? 'viewer');
    canManage = computed(() => ROLE_RANK[this.myRole()] >= ROLE_RANK['admin']);
    isOwner = computed(() => this.myRole() === 'owner');

    // SSO config (admin only)
    sso = signal<any>(null);
    ssoForm = { domain: '', issuer: '', client_id: '', client_secret: '', default_role: 'member' };
    ssoMsg = signal('');

    ngOnInit() {
        this.load();
        if (this.canManage()) this.loadSso();
    }

    loadSso() {
        this.api.getOidcConfig().subscribe({
            next: (res) => {
                this.sso.set(res);
                if (res?.configured) {
                    this.ssoForm.domain = res.domain ?? '';
                    this.ssoForm.issuer = res.issuer ?? '';
                    this.ssoForm.client_id = res.client_id ?? '';
                    this.ssoForm.default_role = res.default_role ?? 'member';
                }
            },
            error: () => {},
        });
    }

    saveSso() {
        this.ssoMsg.set('');
        this.api.putOidcConfig(this.ssoForm).subscribe({
            next: () => {
                this.ssoMsg.set('SSO configuration saved.');
                this.ssoForm.client_secret = '';
                this.loadSso();
            },
            error: (e) => this.ssoMsg.set(e?.error?.error ?? 'Failed to save SSO config'),
        });
    }

    load() {
        this.loading.set(true);
        this.api.getMembers().subscribe({
            next: (res) => {
                this.members.set(res.members ?? []);
                this.invites.set(res.pending_invites ?? []);
                this.loading.set(false);
            },
            error: (e) => {
                this.loading.set(false);
                this.error.set(e?.error?.error ?? 'Failed to load members');
            },
        });
    }

    // Owner role can only be assigned/changed by an owner.
    assignableRoles(): string[] {
        return this.isOwner() ? this.roles : this.roles.filter((r) => r !== 'owner');
    }

    invite() {
        const email = this.inviteEmail.trim();
        if (!email) return;
        this.busy.set(true);
        this.msg.set('');
        this.error.set('');
        this.api.addMember(email, this.inviteRole).subscribe({
            next: (res: any) => {
                this.busy.set(false);
                this.inviteEmail = '';
                if (res?.invited && res?.invite_token) {
                    this.msg.set(`Invite created for ${email}. Share this signup token: ${res.invite_token}`);
                } else {
                    this.msg.set(`${email} added as ${res?.role ?? this.inviteRole}.`);
                }
                this.load();
            },
            error: (e) => {
                this.busy.set(false);
                this.error.set(e?.error?.error ?? 'Failed to add member');
            },
        });
    }

    onRoleChange(m: OrgMember, role: string) {
        if (role === m.role) return;
        this.api.changeMemberRole(m.user_id, role).subscribe({
            next: () => this.load(),
            error: (e) => this.error.set(e?.error?.error ?? 'Failed to change role'),
        });
    }

    remove(m: OrgMember) {
        if (!confirm(`Remove ${m.email} from this organization?`)) return;
        this.api.removeMember(m.user_id).subscribe({
            next: () => this.load(),
            error: (e) => this.error.set(e?.error?.error ?? 'Failed to remove member'),
        });
    }

    roleBadge(role: string): string {
        switch (role) {
            case 'owner':
                return 'border-orange-500/30 bg-orange-500/10 text-orange-200';
            case 'admin':
                return 'border-sky-400/30 bg-sky-400/10 text-sky-100';
            case 'viewer':
                return 'border-white/10 bg-white/[0.03] text-slate-400';
            default:
                return 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200';
        }
    }
}
