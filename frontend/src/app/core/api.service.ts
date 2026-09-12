import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { environment } from '../../environments/environment';

export type ProbeMode = 'headers' | 'graduated';
export type ExportFormat = 'json' | 'csv';

export interface Finding {
  id: number;
  tool: string;
  severity: string;
  category: string | null;
  check: string | null;
  title: string;
  description: string | null;
  target_url: string | null;
  evidence: string | null;
  cvss_score: string | null;
  confidence: string | null;
  detected_at: string;
}

export interface WafDetection {
  id: number;
  vendor: string;
  product: string | null;
  confidence: string | null;
  detection_method: string | null;
  evidence: string | null;
  blocked: boolean;
}

export interface CdnObservation {
  id: number;
  provider: string;
  edge_nodes: string | null;
  origin_hidden: boolean;
  caching: string | null;
  evidence: string | null;
}

export interface Challenge {
  id: number;
  kind: string;
  status_code: number | null;
  headers: string | null;
  bypass_indicators: string | null;
  response_time_ms: number | null;
  severity_hint: string | null;
}

export interface RateLimitObservation {
  id: number;
  scope: string;
  limit: number | null;
  window_seconds: number | null;
  headers: string | null;
  threshold_estimate: number | null;
  recommended_delay_ms: number | null;
}

export interface Analysis {
  id: number;
  target: string;
  status: string;
  analysis_type: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error_message: string | null;
  findings: Finding[];
  waf_detections: WafDetection[];
  cdn_observations: CdnObservation[];
  challenges: Challenge[];
  rate_limit_observations: RateLimitObservation[];
}

export interface AnalysisListItem {
  id: number;
  target: string;
  status: string;
  analysis_type: string;
  created_at: string;
  finding_count: number;
  waf_count: number;
  cdn_count: number;
  challenge_count: number;
  rate_limit_count: number;
}

export interface Guardrail {
  probe_mode: string;
  max_requests: number;
  requests_sent: number;
  aborted: boolean;
  abort_reason: string | null;
  delay_ms_min: number;
  delay_ms_max: number;
}

export interface AnalyzeResponse {
  analysis: Analysis;
  finding_count: number;
  waf_count: number;
  cdn_count: number;
  challenge_count: number;
  rate_limit_count: number;
  guardrail: Guardrail;
}

export interface HealthResponse {
  status: string;
  database: string;
  version: string;
  tool: string;
}

export interface ProbeOptions {
  probe_mode: ProbeMode;
  confirm: boolean;
  max_requests: number;
}

/** xwa-sdk Event envelope as received over the WebSocket. */
export interface LiveEvent {
  seq: number;
  type: string;
  tool: string;
  analysis_id: string;
  ts: string;
  payload: unknown;
}

export function parseJsonArray(value: string | null | undefined): string[] {
  if (!value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map((item) => String(item)) : [];
  } catch {
    return [];
  }
}

export function parseJsonObject(value: string | null | undefined): Record<string, unknown> {
  if (!value) {
    return {};
  }
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly apiUrl = environment.apiBaseUrl;
  private readonly wsUrl = environment.wsBaseUrl;

  health(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>(`${this.apiUrl}/api/health`);
  }

  analyze(target: string, options: ProbeOptions): Observable<AnalyzeResponse> {
    return this.http.post<AnalyzeResponse>(`${this.apiUrl}/api/waf/analyze`, {
      target,
      ...options,
    });
  }

  listAnalyses(): Observable<AnalysisListItem[]> {
    return this.http.get<AnalysisListItem[]>(`${this.apiUrl}/api/analyses`);
  }

  getAnalysis(id: number | string): Observable<Analysis> {
    return this.http.get<Analysis>(`${this.apiUrl}/api/analyses/${id}`);
  }

  deleteAnalysis(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/api/analyses/${id}`);
  }

  deleteAllAnalyses(): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/api/analyses`);
  }

  /** Server-side export URL (Content-Disposition attachment). */
  exportUrl(id: number, format: ExportFormat = 'json'): string {
    return `${this.apiUrl}/api/analyses/${id}/export?format=${format}`;
  }

  /** Live WebSocket endpoint (target URL-encoded). */
  liveUrl(target: string, options: ProbeOptions): string {
    const params = new URLSearchParams({
      target,
      probe_mode: options.probe_mode,
      confirm: String(options.confirm),
      max_requests: String(options.max_requests),
    });
    return `${this.wsUrl}/api/waf/live?${params.toString()}`;
  }
}
