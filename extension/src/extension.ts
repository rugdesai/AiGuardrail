import * as vscode from 'vscode';
import { registerScanAndRunCommand } from './commands/scanAndRun';
import { createStatusBar } from './statusBar';

export function activate(context: vscode.ExtensionContext) {
  console.log('Vibe-Guard Extension activated!');

  const statusBar = createStatusBar();
  context.subscriptions.push(statusBar);

  registerScanAndRunCommand(context, statusBar);
}

export function deactivate() {}
