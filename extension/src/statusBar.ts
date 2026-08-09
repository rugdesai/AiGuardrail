import * as vscode from 'vscode';

export function createStatusBar(): vscode.StatusBarItem {
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  
  statusBar.text = '$(shield) Vibe-Guard';
  statusBar.tooltip = 'AI Code Security Scanner';
  statusBar.show();

  return statusBar;
}
