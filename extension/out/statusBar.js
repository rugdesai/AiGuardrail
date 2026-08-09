"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createStatusBar = createStatusBar;
const vscode = require("vscode");
function createStatusBar() {
    const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBar.text = '$(shield) Vibe-Guard';
    statusBar.tooltip = 'AI Code Security Scanner';
    statusBar.show();
    return statusBar;
}
//# sourceMappingURL=statusBar.js.map