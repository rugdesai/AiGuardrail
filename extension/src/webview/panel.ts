import * as vscode from 'vscode';
import { getWebviewContent } from './webviewContent';
import { analyzeCode } from '../api/client';

export class VibeGuardPanel {
  public static currentPanel: VibeGuardPanel | undefined;
  private readonly _panel: vscode.WebviewPanel;
  private _disposables: vscode.Disposable[] = [];

  public static createOrShow(extensionUri: vscode.Uri) {
    const column = vscode.window.activeTextEditor
      ? vscode.ViewColumn.Beside
      : vscode.ViewColumn.One;

    if (VibeGuardPanel.currentPanel) {
      VibeGuardPanel.currentPanel._panel.reveal(column);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'vibeGuardReport',
      'Vibe-Guard Report',
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    VibeGuardPanel.currentPanel = new VibeGuardPanel(panel, extensionUri);
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;

    // Initial state: empty or welcome
    this._panel.webview.html = getWebviewContent(false);

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
  }

  public async sendCode(code: string, language: string) {
    // 1. Show Loading State (Animated Timeline)
    this._panel.webview.html = getWebviewContent(true);

    // 2. Fetch the mock analysis (takes 2.1 seconds)
    const result = await analyzeCode(code, language);

    // 3. Show the final report
    this._panel.webview.html = getWebviewContent(false, result);

    return result;
  }

  public dispose() {
    VibeGuardPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }
}
