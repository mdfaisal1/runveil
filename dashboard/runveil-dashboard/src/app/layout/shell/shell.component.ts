import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-shell',
  standalone: true,
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive],
  templateUrl: './shell.component.html',
})
export class ShellComponent implements OnInit {
  private auth = inject(AuthService);
  private router = inject(Router);

  user = this.auth.user;

  ngOnInit() {
    if (!this.auth.loaded()) {
      this.auth.refresh().subscribe();
    }
  }

  switchOrg(event: Event) {
    const orgId = (event.target as HTMLSelectElement).value;
    if (orgId && orgId !== this.user()?.org_id) {
      this.auth.switchOrg(orgId).subscribe(() => {
        // Re-load whatever's on screen under the new tenant.
        this.router.navigateByUrl('/projects');
      });
    }
  }

  logout() {
    this.auth.logout().subscribe(() => this.router.navigate(['/login']));
  }
}
