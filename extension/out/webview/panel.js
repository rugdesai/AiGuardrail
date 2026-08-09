"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VibeGuardPanel = void 0;
const vscode = require("vscode");
const webviewContent_1 = require("./webviewContent");
const client_1 = require("../api/client");
class VibeGuardPanel {
    static currentPanel;
    _panel;
    _disposables = [];
    static createOrShow(extensionUri) {
        const column = vscode.window.activeTextEditor
            ? vscode.ViewColumn.Beside
            : vscode.ViewColumn.One;
        if (VibeGuardPanel.currentPanel) {
            VibeGuardPanel.currentPanel._panel.reveal(column);
            return;
        }
        const panel = vscode.window.createWebviewPanel('vibeGuardReport', 'Vibe-Guard Report', column, {
            enableScripts: true,
            retainContextWhenHidden: true,
        });
        VibeGuardPanel.currentPanel = new VibeGuardPanel(panel, extensionUri);
    }
    constructor(panel, extensionUri) {
        this._panel = panel;
        // Initial state: empty or welcome
        this._panel.webview.html = (0, webviewContent_1.getWebviewContent)(false);
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
    }
    async sendCode(code, language) {
        // 1. Show Loading State (Animated Timeline)
        this._panel.webview.html = (0, webviewContent_1.getWebviewContent)(true);
        // 2. Fetch the mock analysis (takes 2.1 seconds)
        const result = await (0, client_1.analyzeCode)(code, language);
        // 3. Show the final report
        this._panel.webview.html = (0, webviewContent_1.getWebviewContent)(false, result);
        return result;
    }
    dispose() {
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
exports.VibeGuardPanel = VibeGuardPanel;
//# sourceMappingURL=panel.js.map