import { Injectable } from '@angular/core';

import {
  Analysis,
  parseJsonArray,
  parseJsonObject,
} from './api.service';

const CSV_HEADER = [
  'record_type',
  'analysis_id',
  'target',
  'severity',
  'category',
  'check',
  'title',
  'description',
  'confidence',
  'vendor',
  'product',
  'detection_method',
  'blocked',
  'provider',
  'origin_hidden',
  'caching',
  'challenge_kind',
  'status_code',
  'bypass_indicators',
  'scope',
  'limit',
  'window_seconds',
  'threshold_estimate',
  'recommended_delay_ms',
];

/**
 * Client-side exports: JSON/CSV blobs and a jsPDF report. The PDF dependency is
 * loaded lazily so the initial bundle stays lean and tests never need jsPDF.
 */
@Injectable({ providedIn: 'root' })
export class ExportService {
  downloadJson(analysis: Analysis): void {
    const blob = new Blob([JSON.stringify(analysis, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    this.download(blob, `kabuki-analysis-${analysis.id}.json`);
  }

  downloadCsv(analysis: Analysis): void {
    const rows: (string | number)[][] = [[...CSV_HEADER]];

    for (const finding of analysis.findings) {
      rows.push([
        'finding',
        analysis.id,
        analysis.target,
        finding.severity,
        finding.category ?? '',
        finding.check ?? '',
        finding.title,
        finding.description ?? '',
        finding.confidence ?? '',
      ]);
    }
    for (const waf of analysis.waf_detections) {
      rows.push([
        'waf_detection',
        analysis.id,
        analysis.target,
        '',
        '',
        '',
        '',
        '',
        waf.confidence ?? '',
        waf.vendor,
        waf.product ?? '',
        waf.detection_method ?? '',
        waf.blocked ? 1 : 0,
      ]);
    }
    for (const cdn of analysis.cdn_observations) {
      rows.push([
        'cdn_observation',
        analysis.id,
        analysis.target,
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        cdn.provider,
        cdn.origin_hidden ? 1 : 0,
        cdn.caching ?? '',
      ]);
    }
    for (const challenge of analysis.challenges) {
      rows.push([
        'challenge',
        analysis.id,
        analysis.target,
        challenge.severity_hint ?? '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        challenge.kind,
        challenge.status_code ?? '',
        parseJsonArray(challenge.bypass_indicators).join(' | '),
      ]);
    }
    for (const rateLimit of analysis.rate_limit_observations) {
      rows.push([
        'rate_limit',
        analysis.id,
        analysis.target,
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        '',
        rateLimit.scope,
        rateLimit.limit ?? '',
        rateLimit.window_seconds ?? '',
        rateLimit.threshold_estimate ?? '',
        rateLimit.recommended_delay_ms ?? '',
      ]);
    }

    const csv = rows.map((row) => row.map((cell) => this.escapeCsv(cell)).join(',')).join('\n');
    this.download(
      new Blob([csv], { type: 'text/csv;charset=utf-8' }),
      `kabuki-analysis-${analysis.id}.csv`,
    );
  }

  async downloadPdf(analysis: Analysis): Promise<void> {
    const { jsPDF } = await import('jspdf');
    const doc = new jsPDF({ unit: 'pt', format: 'a4' });
    const margin = 48;
    let y = margin;

    const line = (text: string, size = 9, style: 'normal' | 'bold' = 'normal', gap = 14) => {
      doc.setFont('courier', style);
      doc.setFontSize(size);
      const wrapped = doc.splitTextToSize(text, 595 - margin * 2) as string[];
      for (const chunk of wrapped) {
        if (y > 800) {
          doc.addPage();
          y = margin;
        }
        doc.text(chunk, margin, y);
        y += gap;
      }
    };

    line('KABUKI / WAF & CDN ANALYSIS', 16, 'bold', 20);
    line(`ANALYSIS #${analysis.id}`, 11, 'bold');
    line(`TARGET:   ${analysis.target}`);
    line(`STATUS:   ${analysis.status}`);
    line(`CREATED:  ${analysis.created_at}`);
    y += 8;

    line('SUMMARY', 11, 'bold');
    line(`FINDINGS: ${analysis.findings.length}`);
    line(`WAF:      ${analysis.waf_detections.length}`);
    line(`CDN:      ${analysis.cdn_observations.length}`);
    line(`CHALLENGES: ${analysis.challenges.length}`);
    line(`RATE LIMIT: ${analysis.rate_limit_observations.length}`);
    y += 8;

    line('WAF DETECTIONS', 11, 'bold');
    for (const waf of analysis.waf_detections) {
      line(
        `- ${waf.vendor}${waf.product ? ' / ' + waf.product : ''} ` +
          `[${(waf.confidence ?? 'unknown').toUpperCase()}] ` +
          `method=${waf.detection_method ?? 'n/a'} blocked=${waf.blocked ? 'yes' : 'no'}`,
      );
    }

    line('CDN', 11, 'bold');
    for (const cdn of analysis.cdn_observations) {
      line(
        `- ${cdn.provider} caching=${cdn.caching ?? 'unknown'} ` +
          `origin_hidden=${cdn.origin_hidden ? 'yes' : 'no'}`,
      );
      const nodes = parseJsonArray(cdn.edge_nodes);
      if (nodes.length) {
        line(`  edge nodes: ${nodes.join(', ')}`, 8, 'normal', 12);
      }
    }

    line('CHALLENGES', 11, 'bold');
    for (const challenge of analysis.challenges) {
      line(
        `- ${challenge.kind} [${(challenge.severity_hint ?? 'info').toUpperCase()}] ` +
          `HTTP ${challenge.status_code ?? 'n/a'} ` +
          `${challenge.response_time_ms ?? '?'} ms`,
      );
      const indicators = parseJsonArray(challenge.bypass_indicators);
      if (indicators.length) {
        line(`  indicators: ${indicators.join(', ')}`, 8, 'normal', 12);
      }
    }

    line('RATE LIMIT', 11, 'bold');
    for (const rateLimit of analysis.rate_limit_observations) {
      line(
        `- scope=${rateLimit.scope} limit=${rateLimit.limit ?? 'n/a'} ` +
          `window=${rateLimit.window_seconds ?? 'n/a'}s ` +
          `delay=${rateLimit.recommended_delay_ms ?? 'n/a'}ms`,
      );
      const headers = Object.entries(parseJsonObject(rateLimit.headers));
      if (headers.length) {
        line(`  headers: ${headers.map(([k, v]) => `${k}=${v}`).join(', ')}`, 8, 'normal', 12);
      }
    }

    line('FINDINGS', 11, 'bold');
    for (const finding of analysis.findings) {
      line(
        `[${finding.severity.toUpperCase()}] ${finding.check ?? finding.category ?? 'finding'} — ` +
          `${finding.title}`,
      );
      if (finding.description) {
        line(`  ${finding.description}`, 8, 'normal', 12);
      }
    }

    doc.save(`kabuki-analysis-${analysis.id}.pdf`);
  }

  private escapeCsv(value: string | number): string {
    const text = String(value ?? '');
    if (/[",\n]/.test(text)) {
      return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
  }

  private download(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.rel = 'noopener';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }
}
