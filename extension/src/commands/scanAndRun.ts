import * as vscode from 'vscode';
import { VibeGuardPanel } from '../webview/panel';

export function registerScanAndRunCommand(
  context: vscode.ExtensionContext,
  statusBar: vscode.StatusBarItem
) {
  const command = vscode.commands.registerCommand(
    'vibeguard.scanAndRun',
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showErrorMessage('No active text editor found.');
        return;
      }

      // Get highlighted code or full file
      const selection = editor.selection;
      const text = selection.isEmpty
        ? editor.document.getText()
        : editor.document.getText(selection);

      const language = editor.document.languageId;

      // Update status bar to show analyzing
      statusBar.text = '$(sync~spin) Analyzing...';
      statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');

      // Create or show the webview panel
      VibeGuardPanel.createOrShow(context.extensionUri);

      // Send the code to the webview and wait for analysis to complete
      let result;
      if (VibeGuardPanel.currentPanel) {
        result = await VibeGuardPanel.currentPanel.sendCode(text, language);
      }

      if (result) {
        if (result.decision === 'BLOCK') {
          statusBar.text = '$(error) Vibe-Guard: Blocked';
          statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        } else if (result.decision === 'WARN') {
          statusBar.text = '$(warning) Vibe-Guard: Warning';
          statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        } else {
          statusBar.text = '$(check) Vibe-Guard: Allowed';
          statusBar.backgroundColor = undefined;
        }
      } else {
        statusBar.text = '$(shield) Vibe-Guard';
        statusBar.backgroundColor = undefined;
      }
    }
  );

  context.subscriptions.push(command);
}
