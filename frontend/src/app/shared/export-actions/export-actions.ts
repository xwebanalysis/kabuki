import { Component, Input, inject } from '@angular/core';

import { Analysis, ApiService } from '../../core/api.service';
import { ExportService } from '../../core/export.service';

@Component({
  selector: 'app-export-actions',
  standalone: true,
  template: `
    <div class="export-actions">
      <button type="button" class="export-btn" (click)="downloadJson()" title="Client-side JSON">
        JSON
      </button>
      <button type="button" class="export-btn" (click)="downloadCsv()" title="Client-side CSV">
        CSV
      </button>
      <button
        type="button"
        class="export-btn"
        (click)="downloadPdf()"
        [disabled]="pdfBusy"
        title="Client-side PDF report"
      >
        {{ pdfBusy ? 'PDF...' : 'PDF' }}
      </button>
      <span class="t-label server-label">SERVER</span>
      <a class="export-btn" [href]="serverJsonUrl()" rel="noopener">JSON</a>
      <a class="export-btn" [href]="serverCsvUrl()" rel="noopener">CSV</a>
    </div>
  `,
  styles: [
    `
      .export-actions {
        display: inline-flex;
        align-items: center;
        gap: var(--space-sm);
        flex-wrap: wrap;
      }

      .server-label {
        margin-left: var(--space-sm);
        color: var(--text-disabled);
      }

      .export-btn {
        display: inline-flex;
        align-items: center;
        border: 1px solid var(--border-visible);
        background-color: transparent;
        color: var(--text-secondary);
        padding: var(--space-sm) var(--space-md);
        font-family: var(--font-data);
        font-size: var(--label);
        letter-spacing: 0.08em;
        text-transform: uppercase;
        min-height: 36px;
        cursor: pointer;
        text-decoration: none;

        &:hover:not(:disabled) {
          color: var(--gold);
          border-color: var(--gold);
          opacity: 1;
        }

        &:disabled {
          opacity: 0.4;
          cursor: not-allowed;
        }
      }
    `,
  ],
})
export class ExportActionsComponent {
  @Input({ required: true }) analysis!: Analysis;

  private readonly api = inject(ApiService);
  private readonly exporter = inject(ExportService);

  protected pdfBusy = false;

  downloadJson(): void {
    this.exporter.downloadJson(this.analysis);
  }

  downloadCsv(): void {
    this.exporter.downloadCsv(this.analysis);
  }

  async downloadPdf(): Promise<void> {
    if (this.pdfBusy) {
      return;
    }
    this.pdfBusy = true;
    try {
      await this.exporter.downloadPdf(this.analysis);
    } finally {
      this.pdfBusy = false;
    }
  }

  serverJsonUrl(): string {
    return this.api.exportUrl(this.analysis.id, 'json');
  }

  serverCsvUrl(): string {
    return this.api.exportUrl(this.analysis.id, 'csv');
  }
}
