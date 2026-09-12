import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { ApiService, parseJsonArray, parseJsonObject } from './api.service';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should GET the health endpoint', () => {
    service.health().subscribe((health) => {
      expect(health.tool).toBe('kabuki');
      expect(health.database).toBe('ok');
    });

    const request = httpMock.expectOne('http://localhost:8040/api/health');
    expect(request.request.method).toBe('GET');
    request.flush({ status: 'ok', database: 'ok', version: '0.1.0', tool: 'kabuki' });
  });

  it('should POST the analyze payload with probe options', () => {
    service
      .analyze('example.com', { probe_mode: 'graduated', confirm: true, max_requests: 7 })
      .subscribe();

    const request = httpMock.expectOne('http://localhost:8040/api/waf/analyze');
    expect(request.request.method).toBe('POST');
    expect(request.request.body).toEqual({
      target: 'example.com',
      probe_mode: 'graduated',
      confirm: true,
      max_requests: 7,
    });
    request.flush({ analysis: { id: 1 } });
  });

  it('should build server-side export URLs', () => {
    expect(service.exportUrl(12, 'json')).toBe(
      'http://localhost:8040/api/analyses/12/export?format=json',
    );
    expect(service.exportUrl(12, 'csv')).toBe(
      'http://localhost:8040/api/analyses/12/export?format=csv',
    );
    expect(service.exportUrl(12)).toContain('format=json');
  });

  it('should build the live WebSocket URL with encoded options', () => {
    const url = service.liveUrl('https://example.com/a b', {
      probe_mode: 'graduated',
      confirm: true,
      max_requests: 5,
    });
    expect(url).toContain('ws://localhost:8040/api/waf/live?');
    expect(url).toContain('target=https%3A%2F%2Fexample.com%2Fa+b');
    expect(url).toContain('probe_mode=graduated');
    expect(url).toContain('confirm=true');
    expect(url).toContain('max_requests=5');
  });

  it('should list, fetch and delete analyses', () => {
    service.listAnalyses().subscribe((items) => expect(items).toEqual([]));
    httpMock.expectOne('http://localhost:8040/api/analyses').flush([]);

    service.getAnalysis(3).subscribe();
    httpMock.expectOne('http://localhost:8040/api/analyses/3').flush({ id: 3 });

    service.deleteAnalysis(3).subscribe();
    const deletion = httpMock.expectOne('http://localhost:8040/api/analyses/3');
    expect(deletion.request.method).toBe('DELETE');
    deletion.flush(null, { status: 204, statusText: 'No Content' });

    service.deleteAllAnalyses().subscribe();
    const deleteAll = httpMock.expectOne('http://localhost:8040/api/analyses');
    expect(deleteAll.request.method).toBe('DELETE');
    deleteAll.flush(null, { status: 204, statusText: 'No Content' });
  });
});

describe('JSON helpers', () => {
  it('should parse arrays and objects safely', () => {
    expect(parseJsonArray('["a","b"]')).toEqual(['a', 'b']);
    expect(parseJsonArray('not-json')).toEqual([]);
    expect(parseJsonArray(null)).toEqual([]);

    expect(parseJsonObject('{"limit":100}')).toEqual({ limit: 100 });
    expect(parseJsonObject('[1,2]')).toEqual({});
    expect(parseJsonObject(null)).toEqual({});
  });
});
