import { Routes } from '@angular/router';

import { AnalyzerComponent } from './features/analyzer/analyzer';
import { HistoryComponent } from './features/history/history';
import { ResultsComponent } from './features/results/results';

export const routes: Routes = [
  { path: '', component: AnalyzerComponent },
  { path: 'analysis/:id', component: ResultsComponent },
  { path: 'history', component: HistoryComponent },
  { path: '**', redirectTo: '' },
];
