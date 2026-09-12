import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';

import { AnalysisListItem, ApiService } from '../../core/api.service';
import { I18nService } from '../../core/i18n.service';
import { StatusBadgeComponent } from '../../shared/status-badge/status-badge';

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [CommonModule, RouterLink, StatusBadgeComponent],
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
