import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { LiveEvent } from './api.service';

/**
 * Thin WebSocket wrapper that exposes xwa-sdk `Event` envelopes as an
 * Observable. Errors emitted by the server arrive as ``analysis_error`` events;
 * transport errors are surfaced through the Observable error channel.
 */
@Injectable({ providedIn: 'root' })
export class LiveService {
  connect(url: string): Observable<LiveEvent> {
    return new Observable<LiveEvent>((subscriber) => {
      const socket = new WebSocket(url);

      socket.onmessage = (message) => {
        try {
          subscriber.next(JSON.parse(message.data) as LiveEvent);
        } catch {
          // Ignore frames that are not valid JSON.
        }
      };

      socket.onerror = () => {
        subscriber.error(new Error('WebSocket transport error'));
      };

      socket.onclose = (event) => {
        if (event.wasClean) {
          subscriber.complete();
        } else {
          subscriber.error(new Error(`WebSocket closed with code ${event.code}`));
        }
      };

      return () => {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
          socket.close(1000, 'client closed');
        }
      };
    });
  }
}
