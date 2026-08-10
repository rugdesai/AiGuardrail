"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCode = analyzeCode;
async function analyzeCode(code, language) {
    // --- INTEGRATION FLAG ---
    // Change this to 'true' when backend is hosted on a public URL!
    const USE_REAL_API = true;
    const API_URL = "https://aiguardrail.onrender.com/analyze"; // TODO: Update with hosted backend URL
    if (!USE_REAL_API) {
        console.log(`[Vibe-Guard] Analyzing ${language} code (MOCK MODE)`);
        await new Promise(resolve => setTimeout(resolve, 2100));
        return {
            executionId: 'mock-' + Date.now(),
            decision: 'BLOCK',
            finalRisk: 91,
            confidence: 0.94,
            staticRisk: 70,
            runtimeRisk: 95,
            aiRisk: 90,
            threats: [
                'Destructive filesystem operation',
                'Shell command execution via os.system'
            ],
            explanation: "The script invokes a recursive delete via os.system('rm -rf').",
            sandboxResult: { exitCode: 0, stdout: '', stderr: '', filesCreated: [], filesModified: [], filesDeleted: [], processesSpawned: [], networkAttempts: [], durationMs: 0, timedOut: false }
        };
    }
    console.log(`[Vibe-Guard] Analyzing ${language} code (REAL MODE)`);
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ codeSnippet: code, language: language })
        });
        const data = await response.json();
        // 1. Calculate decision from their 0-10 score
        let calculatedDecision = 'ALLOW';
        if (data.finalRiskScore >= 7.5) {
            calculatedDecision = 'BLOCK';
        }
        else if (data.finalRiskScore >= 3.0) {
            calculatedDecision = 'WARN';
        }
        // 2. Extract threats from their "diagnostics" list
        const extractedThreats = data.diagnostics
            ? data.diagnostics.map((d) => d.message)
            : [];
        return {
            executionId: data.executionId || ('run_' + Date.now()),
            decision: calculatedDecision,
            finalRisk: Math.round((data.finalRiskScore || 0) * 10), // Scale 0-10 up to 0-100
            confidence: 0.9,
            staticRisk: 0,
            runtimeRisk: 0,
            aiRisk: 0,
            threats: extractedThreats,
            explanation: extractedThreats.length > 0 ? "Threats were detected during analysis." : "Code looks safe.",
            sandboxResult: { exitCode: 0, stdout: '', stderr: '', filesCreated: [], filesModified: [], filesDeleted: [], processesSpawned: [], networkAttempts: [], durationMs: 0, timedOut: false }
        };
    }
    catch (error) {
        console.error("API Error:", error);
        return {
            executionId: 'error',
            decision: 'WARN',
            finalRisk: 50,
            confidence: 0, staticRisk: 0, runtimeRisk: 0, aiRisk: 0,
            threats: ['API connection failed. Make sure backend is running.'],
            explanation: 'Could not connect to backend.',
            sandboxResult: { exitCode: 0, stdout: '', stderr: '', filesCreated: [], filesModified: [], filesDeleted: [], processesSpawned: [], networkAttempts: [], durationMs: 0, timedOut: false }
        };
    }
}
//# sourceMappingURL=client.js.map