import {
  Component,
  ElementRef,
  Input,
  OnChanges,
  ViewChild,
} from '@angular/core';

@Component({
  selector: 'app-terminal',
  standalone: true,
  template: `
    <div class="terminal border-visible">
      <div class="terminal-head">
        <span class="t-label">{{ title }}</span>
        <span class="t-label">{{ lines.length }} LINE(S)</span>
      </div>
      <div class="terminal-body" #scroller>
        @if (lines.length === 0) {
          <div class="terminal-line t-data terminal-empty">{{ emptyText }}</div>
        } @else {
          @for (line of lines; track $index) {
            <div class="terminal-line t-data">{{ line }}</div>
          }
        }
      </div>
    </div>
  `,
  styles: [
    `
      .terminal {
        background-color: var(--black);
        border: 1px solid var(--border-visible);
      }

      .terminal-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: var(--space-sm) var(--space-md);
        border-bottom: 1px solid var(--border);
      }

      .terminal-body {
        height: 280px;
        overflow-y: auto;
        padding: var(--space-sm) var(--space-md);
      }

      .terminal-line {
        font-size: var(--caption);
        line-height: 1.7;
        color: var(--text-primary);
        white-space: pre-wrap;
        word-break: break-word;
      }

      .terminal-empty {
        color: var(--text-disabled);
      }
    `,
  ],
})
export class TerminalComponent implements OnChanges {
  @Input() lines: string[] = [];
  @Input() title = 'LIVE LOG';
  @Input() emptyText = '[ NO EVENTS YET ]';

  @ViewChild('scroller') private scroller?: ElementRef<HTMLElement>;

  ngOnChanges(): void {
    queueMicrotask(() => {
      const element = this.scroller?.nativeElement;
      if (element) {
        element.scrollTop = element.scrollHeight;
      }
    });
  }
}
