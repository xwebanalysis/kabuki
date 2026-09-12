import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-metric-card',
  standalone: true,
  template: `
    <div class="metric border-visible">
      <span class="t-label metric-label">{{ label }}</span>
      <div class="metric-row">
        <span class="metric-value" [class]="'sev-' + (status || 'info')">{{ value }}</span>
        @if (unit) {
          <span class="t-label metric-unit">{{ unit }}</span>
        }
      </div>
    </div>
  `,
  styles: [
    `
      .metric {
        padding: var(--space-md);
        background-color: var(--surface);
        min-width: 0;
      }

      .metric-label {
        display: block;
        margin-bottom: var(--space-sm);
        letter-spacing: 0.12em;
      }

      .metric-row {
        display: flex;
        align-items: baseline;
        gap: var(--space-xs);
      }

      .metric-value {
        font-family: var(--font-display);
        font-size: var(--display-md);
        line-height: 1.05;
        letter-spacing: -0.02em;
      }

      .metric-unit {
        letter-spacing: 0.12em;
      }
    `,
  ],
})
export class MetricCardComponent {
  @Input({ required: true }) label = '';
  @Input() value: string | number = '—';
  @Input() unit = '';
  @Input() status = '';
}
