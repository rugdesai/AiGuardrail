"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const scanAndRun_1 = require("./commands/scanAndRun");
const statusBar_1 = require("./statusBar");
function activate(context) {
    console.log('Vibe-Guard Extension activated!');
    const statusBar = (0, statusBar_1.createStatusBar)();
    context.subscriptions.push(statusBar);
    (0, scanAndRun_1.registerScanAndRunCommand)(context, statusBar);
}
function deactivate() { }
//# sourceMappingURL=extension.js.map