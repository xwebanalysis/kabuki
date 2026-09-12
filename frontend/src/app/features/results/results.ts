import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, Input, OnInit, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import {
  Analysis,
  ApiService,
  CdnObservation,
  Challenge,
  parseJsonArray,
  parseJsonObject,
} from '../../core/api.service';
import { I18nService } from '../../core/i18n.service';
import { ExportActionsComponent } from '../../shared/export-actions/export-actions';
import { MetricCardComponent } from '../../shared/metric-card/metric-card';
import { StatusBadgeComponent } from '../../shared/status-badge/status-badge';

@Component({
  selector: 'app-results',
  standalone: true,
  imports: [CommonModule, MetricCardComponent, StatusBadgeComponent, ExportActionsComponent],
  templateUrl: './results.html',
  styleUrl: './results.scss',
})
export class ResultsComponent implements OnInit {
  @Input() analysis: Analysis | null = null;

  private readonly route = inject(ActivatedRoute);
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  private readonly cdr = inject(ChangeDetectorRef);

  protected loading = false;
  protected error: string | null = null;

  ngOnInit(): void {
    if (!this.analysis) {
      this.loadFromRoute();
    }
  }

  protected t(key: string): string {
    return this.i18n.t(key);
  }

  protected loadFromRoute(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (!id) {
      return;
    }
    this.loading = true;
    this.error = null;
    this.api.getAnalysis(id).subscribe({
      next: (analysis) => {
        this.analysis = analysis;
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: (err) => {
        this.error = err.error?.error?.message ?? 'Failed to load analysis.';
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  protected edgeNodes(cdn: CdnObservation): string[] {
    return parseJsonArray(cdn.edge_nodes);
  }

  protected indicators(challenge: Challenge): string[] {
    return parseJsonArray(challenge.bypass_indicators);
  }

  protected headerEntries(value: string | null): [string, unknown][] {
    return Object.entries(parseJsonObject(value));
  }

  protected severityClass(severity: string | null | undefined): string {
    return `sev-${severity || 'info'}`;
  }
}
