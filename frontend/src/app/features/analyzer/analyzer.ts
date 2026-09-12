import { CommonModule } from '@angular/common';
import { ChangeDetectorRef, Component, OnDestroy, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';

import { Analysis, ApiService, LiveEvent, ProbeMode } from '../../core/api.service';
import { I18nService } from '../../core/i18n.service';
import { LiveService } from '../../core/live.service';
import { TerminalComponent } from '../../shared/terminal/terminal';
import { ResultsComponent } from '../results/results';

type PhaseName = 'fingerprint' | 'challenge' | 'rate_limit' | 'cdn';
type PhaseState = 'pending' | 'running' | 'done';

const PHASES: readonly PhaseName[] = ['fingerprint', 'challenge', 'rate_limit', 'cdn'];

@Component({
  selector: 'app-analyzer',
  standalone: true,
  imports: [CommonModule, FormsModule, TerminalComponent, ResultsComponent],
  templateUrl: './analyzer.html',
  styleUrl: './analyzer.scss',
})
export class AnalyzerComponent implements OnDestroy {
  private readonly api = inject(ApiService);
  private readonly live = inject(LiveService);
  private readonly i18n = inject(I18nService);
  private readonly cdr = inject(ChangeDetectorRef);

  protected readonly phases = PHASES;

  protected target = '';
  protected probeMode: ProbeMode = 'headers';
  protected confirm = false;
  protected maxRequests = 5;

  protected loading = false;
  protected liveRunning = false;
  protected error: string | null = null;
  protected terminalLines: string[] = [];
  protected phaseState: Record<PhaseName, PhaseState> = this.emptyPhases();
  protected analysis: Analysis | null = null;

  private subscription: Subscription | null = null;

  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }

  protected t(key: string): string {
    return this.i18n.t(key);
  }

  protected canRun(): boolean {
    return !!this.target.trim() && !this.loading && !this.liveRunning;
  }

  protected setMode(mode: ProbeMode): void {
    this.probeMode = mode;
    if (mode === 'headers') {
      this.confirm = false;
      this.maxRequests = Math.min(this.maxRequests, 20) || 5;
    }
    if (this.error === this.t('error.confirm')) {
      this.error = null;
    }
  }

  /** REST run: single-shot analysis (headers mode is exactly one probe). */
  protected analyze(): void {
    const target = this.target.trim();
    if (!target || this.loading || this.liveRunning) {
      return;
    }
    if (this.probeMode === 'graduated' && !this.confirm) {
      this.error = this.t('error.confirm');
      this.appendLine(`[BLOCKED] ${this.t('error.confirm')}`);
      return;
    }

    this.loading = true;
    this.error = null;
    this.appendLine(`START REST target=${target} mode=${this.probeMode}`);

    this.api.analyze(target, this.options()).subscribe({
      next: (response) => {
        this.analysis = response.analysis;
        this.appendLine(
          `COMPLETED #${response.analysis.id} findings=${response.finding_count} ` +
            `probes=${response.guardrail.requests_sent}`,
        );
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: (err) => {
        this.error = this.errorMessage(err);
        this.appendLine(`[ERROR] ${this.error}`);
        this.loading = false;
        this.cdr.markForCheck();
      },
    });
  }

  /** WebSocket run with live per-phase progress and a terminal log. */
  protected runLive(): void {
    const target = this.target.trim();
    if (!target || this.loading || this.liveRunning) {
      return;
    }
    if (this.probeMode === 'graduated' && !this.confirm) {
      this.error = this.t('error.confirm');
      this.appendLine(`[BLOCKED] ${this.t('error.confirm')}`);
      return;
    }

    this.liveRunning = true;
    this.error = null;
    this.analysis = null;
    this.terminalLines = [];
    this.phaseState = this.emptyPhases();
    this.appendLine(`OPEN /api/waf/live target=${target} mode=${this.probeMode}`);

    this.subscription = this.live.connect(this.api.liveUrl(target, this.options())).subscribe({
      next: (event) => this.handleEvent(event),
      error: (err) => {
        this.error = err instanceof Error ? err.message : this.t('error.backend');
        this.appendLine(`[ERROR] ${this.error}`);
        this.liveRunning = false;
        this.cdr.markForCheck();
      },
      complete: () => {
        this.liveRunning = false;
        this.cdr.markForCheck();
      },
    });
  }

  protected cancel(): void {
    this.subscription?.unsubscribe();
    this.subscription = null;
    this.appendLine('[CANCELLED] client closed the stream');
    this.liveRunning = false;
  }

  private handleEvent(event: LiveEvent): void {
    switch (event.type) {
      case 'analysis_started':
        this.appendLine(`STARTED #${event.analysis_id}`);
        break;
      case 'analysis_progress': {
        const payload = event.payload as { phase?: string; message?: string } | null;
        const phase = payload?.phase as PhaseName | undefined;
        if (phase) {
          this.markPhase(phase);
          this.appendLine(`[${phase.toUpperCase()}] ${payload?.message ?? ''}`);
        }
        break;
      }
      case 'item_found': {
        const payload = event.payload as Record<string, unknown> | null;
        const kind = String(payload?.['kind'] ?? 'item');
        const label =
          payload?.['vendor'] ??
          payload?.['provider'] ??
          payload?.['challenge_kind'] ??
          payload?.['title'] ??
          payload?.['scope'] ??
          '';
        this.appendLine(`+ ${kind.toUpperCase()} ${label}`.trimEnd());
        break;
      }
      case 'analysis_completed':
        this.phaseState = this.allPhasesDone();
        this.appendLine(`COMPLETED #${event.analysis_id}`);
        this.finishLive(event.analysis_id);
        break;
      case 'analysis_error': {
        const payload = event.payload as
          | { message?: string; error?: { message?: string } }
          | null;
        this.error = payload?.message ?? payload?.error?.message ?? 'Analysis failed.';
        this.appendLine(`[ERROR] ${this.error}`);
        this.liveRunning = false;
        break;
      }
      default:
        this.appendLine(`${event.type} #${event.seq}`);
    }
    this.cdr.markForCheck();
  }

  private finishLive(analysisId: string): void {
    this.api.getAnalysis(analysisId).subscribe({
      next: (analysis) => {
        this.analysis = analysis;
        this.liveRunning = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.liveRunning = false;
        this.cdr.markForCheck();
      },
    });
  }

  private options() {
    return {
      probe_mode: this.probeMode,
      confirm: this.confirm,
      max_requests: Math.min(Math.max(Number(this.maxRequests) || 5, 1), 20),
    };
  }

  private errorMessage(err: unknown): string {
    const httpError = err as { error?: { error?: { message?: string }; detail?: string } };
    return (
      httpError?.error?.error?.message ??
      httpError?.error?.detail ??
      this.t('error.backend')
    );
  }

  private appendLine(line: string): void {
    const stamp = new Date().toISOString().slice(11, 19);
    this.terminalLines = [...this.terminalLines, `${stamp}  ${line}`];
  }

  private markPhase(phase: PhaseName): void {
    const index = PHASES.indexOf(phase);
    for (const [position, name] of PHASES.entries()) {
      if (position < index) {
        this.phaseState[name] = 'done';
      } else if (position === index) {
        this.phaseState[name] = 'running';
      }
    }
  }

  private emptyPhases(): Record<PhaseName, PhaseState> {
    return { fingerprint: 'pending', challenge: 'pending', rate_limit: 'pending', cdn: 'pending' };
  }

  private allPhasesDone(): Record<PhaseName, PhaseState> {
    return { fingerprint: 'done', challenge: 'done', rate_limit: 'done', cdn: 'done' };
  }
}
