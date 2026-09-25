import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';

import { AnalysisListItem, ApiService } from '../../core/api.service';
import { I18nService } from '../../core/i18n.service';
import {
  XwaChartComponent,
  XwaChartColorKey,
  XwaChartDatum,
} from '../../shared/charts/xwa-chart.component';
import { StatusBadgeComponent } from '../../shared/status-badge/status-badge';

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [CommonModule, RouterLink, StatusBadgeComponent, XwaChartComponent],
  templateUrl: './history.html',
  styleUrl: './history.scss',
})
export class HistoryComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);
  private readonly cdr = inject(ChangeDetectorRef);

  protected history: AnalysisListItem[] = [];
  protected loading = false;
  protected error: string | null = null;
  protected notice: string | null = null;

  ngOnInit(): void {
    this.load();
  }

  protected t(key: string): string {
    return this.i18n.t(key);
  }

  /** Analyses per calendar day (UTC date prefix) for the line chart. */
  protected get analysesPerDayData(): XwaChartDatum[] {
    const byDay = new Map<string, number>();
    for (const item of this.history) {
      const day = String(item.created_at ?? '').slice(0, 10) || 'UNKNOWN';
      byDay.set(day, (byDay.get(day) ?? 0) + 1);
    }
    return [...byDay.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([label, value]) => ({ label, value }));
  }

  /** Analyses grouped by status for the donut chart. */
  protected get statusChartData(): XwaChartDatum[] {
    const counts = new Map<string, number>();
    for (const item of this.history) {
      const key = String(item.status || 'UNKNOWN').toUpperCase();
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].map(([label, value]) => ({
      label,
      value,
      color: this.statusColor(label),
    }));
  }

  private statusColor(status: string): XwaChartColorKey {
    if (status === 'COMPLETED') return 'success';
    if (status === 'RUNNING' || status === 'PENDING') return 'warning';
    if (status === 'ERROR' || status === 'CANCELLED' || status === 'FAILED') return 'critical';
    return 'neutral-strong';
  }

  protected load(): void {
    this.loading = true;
    this.error = null;
    this.api.listAnalyses().subscribe({
      next: (items) => {
        this.history = items;
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.error = this.t('error.backend');
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  protected remove(id: number): void {
    this.api.deleteAnalysis(id).subscribe({
      next: () => {
        this.history = this.history.filter((item) => item.id !== id);
        this.notice = '[DELETED]';
        this.cdr.markForCheck();
      },
      error: () => {
        this.error = 'Failed to delete analysis.';
        this.cdr.markForCheck();
      },
    });
  }

  protected removeAll(): void {
    this.api.deleteAllAnalyses().subscribe({
      next: () => {
        this.history = [];
        this.notice = '[DELETED ALL]';
        this.cdr.markForCheck();
      },
      error: () => {
        this.error = 'Failed to delete analyses.';
        this.cdr.markForCheck();
      },
    });
  }
}
