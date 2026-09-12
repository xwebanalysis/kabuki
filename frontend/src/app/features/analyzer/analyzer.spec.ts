import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';

import { Analysis, ApiService, AnalyzeResponse } from '../../core/api.service';
import { LiveService } from '../../core/live.service';
import { AnalyzerComponent } from './analyzer';

const analysis = {
  id: 7,
  target: 'https://example.com',
  status: 'COMPLETED',
  analysis_type: 'waf_profile',
  created_at: '2026-09-12T10:00:00',
  started_at: null,
  finished_at: null,
  error_message: null,
  findings: [],
  waf_detections: [],
  cdn_observations: [],
  challenges: [],
  rate_limit_observations: [],
} as unknown as Analysis;

const analyzeResponse = {
  analysis,
  finding_count: 3,
  waf_count: 1,
  cdn_count: 0,
  challenge_count: 0,
  rate_limit_count: 1,
  guardrail: {
    probe_mode: 'graduated',
    max_requests: 5,
    requests_sent: 2,
    aborted: true,
    abort_reason: 'HTTP 429 on probe 2',
    delay_ms_min: 500,
    delay_ms_max: 1500,
  },
} as unknown as AnalyzeResponse;

describe('AnalyzerComponent', () => {
  let fixture: ComponentFixture<AnalyzerComponent>;
  let component: any;
  const apiStub = {
    analyze: vi.fn(),
    getAnalysis: vi.fn(),
    liveUrl: vi.fn((target: string, options: unknown) => `ws://test/live?target=${target}`),
  };
  const liveStub = { connect: vi.fn() };

  beforeEach(async () => {
    localStorage.clear();
    apiStub.analyze.mockReset();
    apiStub.getAnalysis.mockReset();
    liveStub.connect.mockReset();

    await TestBed.configureTestingModule({
      imports: [AnalyzerComponent],
      providers: [
        { provide: ApiService, useValue: apiStub },
        { provide: LiveService, useValue: liveStub },
      ],
    }).compileComponents();

    fixture = TestBed.createComponent(AnalyzerComponent);
    component = fixture.componentInstance;
  });

  it('should block graduated probing without explicit confirm', () => {
    component.target = 'example.com';
    component.probeMode = 'graduated';
    component.confirm = false;

    component.analyze();

    expect(apiStub.analyze).not.toHaveBeenCalled();
    expect(component.error).toContain('CONFIRM');
    expect(component.terminalLines.some((line: string) => line.includes('[BLOCKED]'))).toBe(true);
  });

  it('should run a REST analysis when graduated probing is confirmed', () => {
    apiStub.analyze.mockReturnValue(of(analyzeResponse));
    component.target = 'example.com';
    component.probeMode = 'graduated';
    component.confirm = true;
    component.maxRequests = 5;

    component.analyze();

    expect(apiStub.analyze).toHaveBeenCalledWith('example.com', {
      probe_mode: 'graduated',
      confirm: true,
      max_requests: 5,
    });
    expect(component.analysis?.id).toBe(7);
    expect(component.loading).toBe(false);
  });

  it('should consume live events and load the persisted analysis', () => {
    apiStub.getAnalysis.mockReturnValue(of(analysis));
    liveStub.connect.mockReturnValue(
      of(
        {
          seq: 1,
          type: 'analysis_started',
          tool: 'kabuki',
          analysis_id: '7',
          ts: '2026-09-12T10:00:00Z',
          payload: { target: 'example.com' },
        },
        {
          seq: 2,
          type: 'analysis_progress',
          tool: 'kabuki',
          analysis_id: '7',
          ts: '2026-09-12T10:00:01Z',
          payload: { phase: 'fingerprint', message: 'Probing example.com' },
        },
        {
          seq: 3,
          type: 'item_found',
          tool: 'kabuki',
          analysis_id: '7',
          ts: '2026-09-12T10:00:02Z',
          payload: { kind: 'waf', vendor: 'Cloudflare' },
        },
        {
          seq: 4,
          type: 'analysis_completed',
          tool: 'kabuki',
          analysis_id: '7',
          ts: '2026-09-12T10:00:03Z',
          payload: { summary: { waf_count: 1 } },
        },
      ),
    );

    component.target = 'example.com';
    component.runLive();

    expect(liveStub.connect).toHaveBeenCalledTimes(1);
    expect(apiStub.liveUrl).toHaveBeenCalledWith(
      'example.com',
      expect.objectContaining({ probe_mode: 'headers', confirm: false }),
    );
    expect(component.terminalLines.some((line: string) => line.includes('[FINGERPRINT]'))).toBe(
      true,
    );
    expect(component.terminalLines.some((line: string) => line.includes('+ WAF Cloudflare'))).toBe(
      true,
    );
    expect(component.analysis?.id).toBe(7);
    expect(component.liveRunning).toBe(false);
  });

  it('should surface analysis_error events inline', () => {
    liveStub.connect.mockReturnValue(
      of({
        seq: 2,
        type: 'analysis_error',
        tool: 'kabuki',
        analysis_id: '7',
        ts: '2026-09-12T10:00:00Z',
        payload: { error: { code: 'TARGET_ERROR', message: 'connection refused' } },
      }),
    );

    component.target = 'bad.example';
    component.runLive();

    expect(component.error).toContain('connection refused');
    expect(component.liveRunning).toBe(false);
  });
});
