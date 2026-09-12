import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-status-badge',
  standalone: true,
  template: `<span class="t-label badge" [class]="statusClass()">[ {{ status }} ]</span>`,
  styles: [
    `
      .badge {
        letter-spacing: 0.12em;
        white-space: nowrap;
      }
    `,
  ],
})
export class StatusBadgeComponent {
  @Input({ required: true }) status = '';

  statusClass(): string {
    switch (this.status) {
      case 'COMPLETED':
        return 'text-success';
      case 'RUNNING':
      case 'PENDING':
        return 'text-warning';
      case 'ERROR':
      case 'CANCELLED':
        return 'text-accent';
      default:
        return 'text-muted';
    }
  }
}
