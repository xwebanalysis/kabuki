import { ChangeDetectorRef, Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { ApiService } from './core/api.service';
import { I18nService } from './core/i18n.service';
import { ThemeService } from './core/theme.service';

@Component({
  selector: 'app-root',
  imports: [CommonModule, RouterLink, RouterLinkActive, RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App implements OnInit {
  private readonly api = inject(ApiService);
  private readonly theme = inject(ThemeService);
  private readonly i18n = inject(I18nService);
  private readonly cdr = inject(ChangeDetectorRef);

  protected backendOnline = false;

  ngOnInit(): void {
    this.theme.initTheme();
    this.api.health().subscribe({
      next: () => {
        this.backendOnline = true;
        this.cdr.markForCheck();
      },
      error: () => {
        this.backendOnline = false;
        this.cdr.markForCheck();
      },
    });
  }

  protected t(key: string): string {
    return this.i18n.t(key);
  }

  protected toggleTheme(): void {
    this.theme.toggleTheme();
  }

  protected themeLabel(): string {
    return this.theme.nextThemeLabel();
  }

  protected toggleLocale(): void {
    this.i18n.toggle();
  }

  protected localeLabel(): string {
    return this.i18n.locale().toUpperCase();
  }
}
