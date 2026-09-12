import { TestBed } from '@angular/core/testing';

import { Analysis, ApiService } from '../../core/api.service';
import { ExportService } from '../../core/export.service';
import { ExportActionsComponent } from './export-actions';

const analysis = {
  id: 9,
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

describe('ExportActionsComponent', () => {
  const exporterStub = {
    downloadJson: vi.fn(),
    downloadCsv: vi.fn(),
    downloadPdf: vi.fn().mockResolvedValue(undefined),
  };
  const apiStub = {
    exportUrl: (id: number, format: string) =>
      `http://localhost:8040/api/analyses/${id}/export?format=${format}`,
  };

  beforeEach(async () => {
    exporterStub.downloadJson.mockClear();
    exporterStub.downloadCsv.mockClear();
    exporterStub.downloadPdf.mockClear();

    await TestBed.configureTestingModule({
      imports: [ExportActionsComponent],
      providers: [
        { provide: ExportService, useValue: exporterStub },
        { provide: ApiService, useValue: apiStub },
      ],
    }).compileComponents();
  });

  it('should render client buttons and server links', () => {
    const fixture = TestBed.createComponent(ExportActionsComponent);
    fixture.componentInstance.analysis = analysis;
    fixture.detectChanges();

    const element = fixture.nativeElement as HTMLElement;
    const buttons = Array.from(element.querySelectorAll('button.export-btn')).map(
      (button) => button.textContent?.trim(),
    );
    expect(buttons).toEqual(['JSON', 'CSV', 'PDF']);

    const links = Array.from(element.querySelectorAll('a.export-btn')).map((link) =>
      link.getAttribute('href'),
    );
    expect(links).toEqual([
      'http://localhost:8040/api/analyses/9/export?format=json',
      'http://localhost:8040/api/analyses/9/export?format=csv',
    ]);
  });

  it('should delegate client exports to the export service', async () => {
    const fixture = TestBed.createComponent(ExportActionsComponent);
    fixture.componentInstance.analysis = analysis;
    fixture.detectChanges();

    const buttons = fixture.nativeElement.querySelectorAll('button.export-btn');
    buttons[0].click();
    buttons[1].click();
    await fixture.componentInstance.downloadPdf();

    expect(exporterStub.downloadJson).toHaveBeenCalledWith(analysis);
    expect(exporterStub.downloadCsv).toHaveBeenCalledWith(analysis);
    expect(exporterStub.downloadPdf).toHaveBeenCalledWith(analysis);
  });

  it('should build server URLs for the current analysis', () => {
    const fixture = TestBed.createComponent(ExportActionsComponent);
    fixture.componentInstance.analysis = analysis;
    expect(fixture.componentInstance.serverJsonUrl()).toContain('/analyses/9/export?format=json');
    expect(fixture.componentInstance.serverCsvUrl()).toContain('/analyses/9/export?format=csv');
  });
});
