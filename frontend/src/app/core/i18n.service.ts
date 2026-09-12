import { Injectable, signal } from '@angular/core';

export type Locale = 'en' | 'es';

const TRANSLATIONS: Record<Locale, Record<string, string>> = {
  en: {
    'app.tagline': 'XWA - MODULE',
    'nav.analyzer': 'ANALYZER',
    'nav.history': 'HISTORY',
    'dashboard.title': 'WAF & CDN ANALYSIS',
    'dashboard.subtitle': 'FINGERPRINT / CHALLENGE / RATE-LIMIT / CDN MAPPING',
    'target.label': 'TARGET',
    'target.placeholder': 'https://example.com',
    'probe.label': 'PROBE MODE',
    'probe.headers': 'HEADERS',
    'probe.graduated': 'GRADUATED',
    'probe.confirm': 'CONFIRM GRADUATED PROBING (SLOW, ABORTS ON 429/403)',
    'probe.max': 'MAX REQUESTS',
    'action.analyze': 'ANALYZE',
    'action.live': 'LIVE STREAM',
    'action.cancel': 'CANCEL',
    'action.analyzing': 'ANALYZING...',
    'error.confirm': 'CONFIRM REQUIRED FOR GRADUATED PROBING',
    'error.backend': 'FAILED TO REACH THE BACKEND',
    'terminal.title': 'LIVE LOG',
    'terminal.empty': '[ NO EVENTS YET ]',
    'results.title': 'ANALYSIS',
    'results.findings': 'FINDINGS',
    'results.waf': 'WAF',
    'results.cdn': 'CDN',
    'results.challenges': 'CHALLENGES',
    'results.rate_limit': 'RATE LIMIT',
    'results.no_waf': '[ NO WAF DETECTED ]',
    'results.no_cdn': '[ NO CDN DETECTED ]',
    'results.no_challenges': '[ NO CHALLENGES OBSERVED ]',
    'results.no_rate_limit': '[ NO RATE-LIMIT DATA ]',
    'history.title': 'HISTORY',
    'history.subtitle': 'RECENT ANALYSES',
    'history.empty': '[ NO ANALYSES YET ]',
    'history.delete_all': 'DELETE ALL',
  },
  es: {
    'app.tagline': 'XWA - MODULO',
    'nav.analyzer': 'ANALIZADOR',
    'nav.history': 'HISTORIAL',
    'dashboard.title': 'ANALISIS WAF Y CDN',
    'dashboard.subtitle': 'FINGERPRINT / RETOS / RATE-LIMIT / MAPEO CDN',
    'target.label': 'OBJETIVO',
    'target.placeholder': 'https://ejemplo.com',
    'probe.label': 'MODO DE SONDA',
    'probe.headers': 'CABECERAS',
    'probe.graduated': 'GRADUADO',
    'probe.confirm': 'CONFIRMAR SONDA GRADUADA (LENTA, ABORTA EN 429/403)',
    'probe.max': 'MAX PETICIONES',
    'action.analyze': 'ANALIZAR',
    'action.live': 'STREAM EN VIVO',
    'action.cancel': 'CANCELAR',
    'action.analyzing': 'ANALIZANDO...',
    'error.confirm': 'SE REQUIERE CONFIRMACION PARA LA SONDA GRADUADA',
    'error.backend': 'NO SE PUDO ALCANZAR EL BACKEND',
    'terminal.title': 'LOG EN VIVO',
    'terminal.empty': '[ SIN EVENTOS TODAVIA ]',
    'results.title': 'ANALISIS',
    'results.findings': 'HALLAZGOS',
    'results.waf': 'WAF',
    'results.cdn': 'CDN',
    'results.challenges': 'RETOS',
    'results.rate_limit': 'RATE LIMIT',
    'results.no_waf': '[ SIN WAF DETECTADO ]',
    'results.no_cdn': '[ SIN CDN DETECTADO ]',
    'results.no_challenges': '[ SIN RETOS OBSERVADOS ]',
    'results.no_rate_limit': '[ SIN DATOS DE RATE-LIMIT ]',
    'history.title': 'HISTORIAL',
    'history.subtitle': 'ANALISIS RECIENTES',
    'history.empty': '[ SIN ANALISIS TODAVIA ]',
    'history.delete_all': 'BORRAR TODO',
  },
};

@Injectable({ providedIn: 'root' })
export class I18nService {
  private readonly storageKey = 'kabuki-locale';
  readonly locale = signal<Locale>(this.readStoredLocale());

  t(key: string): string {
    return TRANSLATIONS[this.locale()][key] ?? key;
  }

  toggle(): void {
    this.setLocale(this.locale() === 'en' ? 'es' : 'en');
  }

  setLocale(locale: Locale): void {
    this.locale.set(locale);
    localStorage.setItem(this.storageKey, locale);
  }

  private readStoredLocale(): Locale {
    const stored = localStorage.getItem(this.storageKey);
    return stored === 'es' ? 'es' : 'en';
  }
}
