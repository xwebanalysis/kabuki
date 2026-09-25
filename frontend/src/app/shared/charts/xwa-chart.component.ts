import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';

export type XwaChartColorKey =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'neutral'
  | 'neutral-strong'
  | 'interactive'
  | 'success'
  | 'warning';

export interface XwaChartDatum {
  label: string;
  value: number;
  color?: XwaChartColorKey;
}

export type XwaChartKind = 'donut' | 'h-bars' | 'bars' | 'line';

/** CSS-variable color map so charts follow dark/light mode automatically. */
export const XWA_CHART_COLORS: Record<XwaChartColorKey, string> = {
  critical: 'var(--accent)',
  high: 'var(--accent)',
  medium: 'var(--warning)',
  low: 'var(--success)',
  info: 'var(--interactive)',
  neutral: 'var(--border-visible)',
  'neutral-strong': 'var(--text-secondary)',
  interactive: 'var(--interactive)',
  success: 'var(--success)',
  warning: 'var(--warning)'
};

/** Default categorical sequence used when a datum has no explicit color. */
const DEFAULT_SEQUENCE: XwaChartColorKey[] = [
  'interactive',
  'warning',
  'success',
  'critical',
  'neutral-strong',
  'neutral'
];

interface ChartRow {
  label: string;
  value: number;
  color: string;
  pct: number;
}

interface DonutArc {
  path: string;
  color: string;
}

interface BarColumn {
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
  value: number;
  color: string;
}

interface LineGeometry {
  points: string;
  dots: Array<{ x: number; y: number }>;
  labels: Array<{ x: number; label: string }>;
  values: Array<{ x: number; y: number; label: string }>;
  maxValue: number;
}

/**
 * Nothing Design SVG chart: monochrome, Space Mono, CSS-variable colors.
 * No chart libraries, no gradients, no shadows. Flat instrument style.
 */
@Component({
  selector: 'app-xwa-chart',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './xwa-chart.component.html',
  styleUrls: ['./xwa-chart.component.scss']
})
export class XwaChartComponent {
  @Input() kind: XwaChartKind = 'h-bars';
  @Input() data: XwaChartDatum[] = [];
  @Input() title = '';
  @Input() unit = '';

  get hasData(): boolean {
    return (this.data ?? []).some((d) => d.value > 0);
  }

  get rows(): ChartRow[] {
    const total = this.total;
    return (this.data ?? [])
      .filter((d) => d.value > 0)
      .map((d, i) => ({
        label: d.label,
        value: d.value,
        color: XWA_CHART_COLORS[d.color ?? DEFAULT_SEQUENCE[i % DEFAULT_SEQUENCE.length]],
        pct: total > 0 ? Math.round((d.value / total) * 100) : 0
      }));
  }

  get total(): number {
    return (this.data ?? []).reduce((sum, d) => sum + (d.value > 0 ? d.value : 0), 0);
  }

  get maxValue(): number {
    return Math.max(1, ...this.rows.map((r) => r.value));
  }

  get viewBox(): string {
    switch (this.kind) {
      case 'donut':
        return '0 0 112 112';
      case 'h-bars':
        return `0 0 320 ${Math.max(56, 10 + this.rows.length * 26)}`;
      case 'bars':
        return '0 0 320 200';
      case 'line':
        return '0 0 320 200';
    }
  }

  get gridLines(): Array<{ x1: number; y1: number; x2: number; y2: number }> {
    if (this.kind === 'h-bars' || this.kind === 'donut') return [];
    const top = this.kind === 'bars' ? 16 : 24;
    const bottom = this.kind === 'bars' ? 168 : 156;
    return [0.25, 0.5, 0.75, 1].map((g) => ({
      x1: 36,
      y1: bottom - (bottom - top) * g,
      x2: 316,
      y2: bottom - (bottom - top) * g
    }));
  }

  get hBarRows(): Array<{ label: string; value: string; color: string; width: number }> {
    const max = this.maxValue;
    return this.rows.map((r) => ({
      label: this.truncate(r.label, 16),
      value: `${r.value}${this.unit}`,
      color: r.color,
      width: Math.max(3, Math.round((r.value / max) * 176))
    }));
  }

  get donutArcs(): DonutArc[] {
    const cx = 56;
    const cy = 56;
    const r = 40;
    const total = this.total;
    let angle = -Math.PI / 2;
    const gap = this.rows.length > 1 ? 0.035 : 0;
    return this.rows.map((row) => {
      const sweep = (row.value / total) * Math.PI * 2;
      const a0 = angle + gap / 2;
      const a1 = angle + sweep - gap / 2;
      angle += sweep;
      const large = sweep > Math.PI ? 1 : 0;
      const x0 = cx + r * Math.cos(a0);
      const y0 = cy + r * Math.sin(a0);
      const x1 = cx + r * Math.cos(a1);
      const y1 = cy + r * Math.sin(a1);
      return {
        color: row.color,
        path: `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`
      };
    });
  }

  get donutLegend(): Array<{ color: string; label: string; value: string }> {
    return this.rows.slice(0, 6).map((r) => ({
      color: r.color,
      label: this.truncate(r.label, 22),
      value: `${r.value} (${r.pct}%)`
    }));
  }

  get barColumns(): BarColumn[] {
    const n = Math.max(1, this.rows.length);
    const slot = 320 / n;
    const barW = Math.min(26, slot * 0.5);
    const bottom = 168;
    const top = 16;
    const max = this.maxValue;
    return this.rows.map((r, i) => {
      const h = Math.max(2, (r.value / max) * (bottom - top));
      return {
        x: i * slot + slot / 2 - barW / 2,
        y: bottom - h,
        w: barW,
        h,
        label: this.truncate(r.label, 9),
        value: r.value,
        color: r.color
      };
    });
  }

  get lineGeometry(): LineGeometry {
    const left = 40;
    const right = 314;
    const top = 22;
    const bottom = 154;
    const n = this.rows.length;
    const max = this.maxValue;
    const niceMax = this.niceCeil(max);
    const span = n > 1 ? right - left : 0;
    const pts = this.rows.map((r, i) => {
      const x = n > 1 ? left + (span * i) / (n - 1) : (left + right) / 2;
      const y = bottom - (r.value / niceMax) * (bottom - top);
      return { x, y };
    });
    const labelStep = Math.max(1, Math.ceil(n / 8));
    const labels = pts
      .map((p, i) => ({ x: p.x, label: this.truncate(this.rows[i].label, 10) }))
      .filter((_, i) => i % labelStep === 0);
    const values = n <= 12 ? pts.map((p, i) => ({ x: p.x, y: p.y, label: String(this.rows[i].value) })) : [];
    return {
      points: pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' '),
      dots: pts.map((p) => ({ x: p.x, y: p.y })),
      labels,
      values,
      maxValue: niceMax
    };
  }

  chartAriaLabel(): string {
    if (!this.hasData) {
      return this.title ? `${this.title}: no data` : 'Chart: no data';
    }
    const body = this.rows.map((r) => `${r.label} ${r.value}`).join(', ');
    return this.title ? `${this.title}: ${body}` : body;
  }

  private niceCeil(value: number): number {
    if (value <= 4) return 4;
    const pow = Math.pow(10, Math.floor(Math.log10(value)));
    for (const mult of [1, 2, 2.5, 5, 10]) {
      if (value <= pow * mult) return pow * mult;
    }
    return pow * 10;
  }

  private truncate(value: string, max: number): string {
    return value.length > max ? `${value.slice(0, max - 1)}…` : value;
  }
}
