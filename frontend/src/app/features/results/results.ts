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
import {
  XwaChartComponent,
  XwaChartColorKey,
  XwaChartDatum,
} from '../../shared/charts/xwa-chart.component';
import { ExportActionsComponent } from '../../shared/export-actions/export-actions';
import { MetricCardComponent } from '../../shared/metric-card/metric-card';
import { StatusBadgeComponent } from '../../shared/status-badge/status-badge';

@Component({
  selector: 'app-results',
  standalone: true,
  imports: [
    CommonModule,
    MetricCardComponent,
    StatusBadgeComponent,
    ExportActionsComponent,
    XwaChartComponent,
  ],
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

  /** Findings grouped by category (waf/cdn/challenge/rate_limit) for the h-bars chart. */
  protected get categoryChartData(): XwaChartDatum[] {
    const findings = this.analysis?.findings ?? [];
    const known: Array<{ key: string; label: string; color: XwaChartColorKey }> = [
      { key: 'waf', label: 'WAF', color: 'critical' },
      { key: 'cdn', label: 'CDN', color: 'interactive' },
      { key: 'challenge', label: 'CHALLENGE', color: 'warning' },
      { key: 'rate_limit', label: 'RATE LIMIT', color: 'success' },
    ];
    const data = known.map((entry) => ({
      label: entry.label,
      value: findings.filter((f) => (f.category ?? '').toLowerCase() === entry.key).length,
      color: entry.color,
    }));
    const other = findings.filter(
      (f) => !known.some((entry) => (f.category ?? '').toLowerCase() === entry.key),
    ).length;
    if (other > 0) {
      data.push({ label: 'OTHER', value: other, color: 'neutral-strong' });
    }
    return data;
  }

  /** Findings grouped by severity for the donut chart (critical/high/medium/low/info). */
  protected get severityChartData(): XwaChartDatum[] {
    const findings = this.analysis?.findings ?? [];
    const data: Array<{ label: string; color: XwaChartColorKey }> = [
      { label: 'CRITICAL', color: 'critical' },
      { label: 'HIGH', color: 'warning' },
      { label: 'MEDIUM', color: 'neutral-strong' },
      { label: 'LOW', color: 'success' },
      { label: 'INFO', color: 'interactive' },
    ];
    const counts = data.map((entry) => ({
      label: entry.label,
      value: findings.filter((f) => f.severity === entry.label.toLowerCase()).length,
      color: entry.color,
    }));
    // Surface any 'pass'-severity findings instead of silently dropping them.
    const pass = findings.filter((f) => f.severity === 'pass').length;
    if (pass > 0) {
      counts.push({ label: 'PASS', value: pass, color: 'success' });
    }
    return counts;
  }
}
