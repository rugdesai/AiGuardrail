"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCode = analyzeCode;
async function analyzeCode(code, language) {
    // ---------------------------------------------------------
    // INTEGRATION FLAG
    // ---------------------------------------------------------
    const USE_REAL_API = true;
    // IMPORTANT:
    // Keep this as a plain URL. Do NOT put markdown [ ] ( ).
    const API_URL = "http://10.66.75.148:8000/analyze";
    // ---------------------------------------------------------
    // MOCK MODE
    // ---------------------------------------------------------
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
            diagnostics: [
                {
                    type: 'CRITICAL',
                    message: 'Destructive filesystem operation',
                    severity: 'CRITICAL',
                    confidence: 0.94,
                    cwe: 'CWE-78',
                    owasp: 'A05:2025-Injection',
                    remediation: 'Avoid executing untrusted shell commands. Validate and constrain input before execution.'
                }
            ],
            status: 'CRITICAL',
            aiEngine: 'Mock AI',
            llmInvoked: false,
            llmReason: 'Mock mode enabled.',
            summary: {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0
            },
            sandboxResult: {
                exitCode: 0,
                stdout: '',
                stderr: '',
                filesCreated: [],
                filesModified: [],
                filesDeleted: [],
                processesSpawned: [],
                networkAttempts: [],
                durationMs: 0,
                timedOut: false
            }
        };
    }
    // ---------------------------------------------------------
    // REAL BACKEND MODE
    // ---------------------------------------------------------
    console.log(`[Vibe-Guard] Analyzing ${language} code (REAL MODE)`);
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                codeSnippet: code,
                language: language,
                userPrompt: 'Find security vulnerabilities'
            })
        });
        // -------------------------------------------------------
        // HTTP ERROR CHECK
        // -------------------------------------------------------
        if (!response.ok) {
            throw new Error(`Backend returned HTTP ${response.status}`);
        }
        const data = await response.json();
        console.log('[Vibe-Guard] Backend response:', data);
        // -------------------------------------------------------
        // CALCULATE DECISION
        // Backend gives risk from 0-10
        // -------------------------------------------------------
        let calculatedDecision = 'ALLOW';
        if (data.finalRiskScore >= 7.5) {
            calculatedDecision = 'BLOCK';
        }
        else if (data.finalRiskScore >= 3.0) {
            calculatedDecision = 'WARN';
        }
        // -------------------------------------------------------
        // EXTRACT FULL DIAGNOSTICS
        // -------------------------------------------------------
        const diagnostics = Array.isArray(data.diagnostics)
            ? data.diagnostics
            : [];
        // Simple messages for the existing UI
        const extractedThreats = diagnostics
            .map((diagnostic) => diagnostic.message || 'Security issue detected.')
            .filter(Boolean);
        // -------------------------------------------------------
        // SANDBOX DATA
        // -------------------------------------------------------
        const sandbox = data.sandbox || {};
        // -------------------------------------------------------
        // ANALYZER STATUS
        // -------------------------------------------------------
        const analyzers = data.analyzers || {};
        // The backend currently doesn't appear to provide
        // individual 0-100 component risk scores.
        //
        // Keep these at 0 unless the backend starts returning:
        // staticRisk, runtimeRisk, aiRisk.
        //
        // This avoids inventing fake risk numbers.
        const staticRisk = typeof data.staticRisk === 'number'
            ? data.staticRisk
            : 0;
        const runtimeRisk = typeof data.runtimeRisk === 'number'
            ? data.runtimeRisk
            : 0;
        const aiRisk = typeof data.aiRisk === 'number'
            ? data.aiRisk
            : 0;
        // -------------------------------------------------------
        // EXPLANATION
        // -------------------------------------------------------
        let explanation = extractedThreats.length > 0
            ? 'Security threats were detected during analysis.'
            : 'Code looks safe.';
        // If backend provided a useful reason, prefer it
        if (data.llmReason) {
            explanation = data.llmReason;
        }
        // -------------------------------------------------------
        // RETURN COMPLETE RESULT
        // -------------------------------------------------------
        return {
            executionId: data.executionId ||
                ('run_' + Date.now()),
            decision: calculatedDecision,
            // Backend = 0-10
            // Frontend = 0-100
            finalRisk: Math.round((data.finalRiskScore || 0) * 10),
            confidence: diagnostics.length > 0 &&
                typeof diagnostics[0].confidence === 'number'
                ? diagnostics[0].confidence
                : 0.9,
            staticRisk,
            runtimeRisk,
            aiRisk,
            threats: extractedThreats,
            explanation,
            // FULL vulnerability information
            diagnostics,
            // Backend metadata
            status: data.status,
            aiEngine: data.aiEngine,
            llmInvoked: data.llmInvoked,
            llmReason: data.llmReason,
            // Critical / High / Medium / Low counts
            summary: data.summary
                ? {
                    critical: data.summary.critical || 0,
                    high: data.summary.high || 0,
                    medium: data.summary.medium || 0,
                    low: data.summary.low || 0
                }
                : {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0
                },
            // Sandbox information
            sandboxResult: {
                exitCode: sandbox.exitCode || 0,
                stdout: sandbox.stdout || '',
                stderr: sandbox.stderr || '',
                filesCreated: sandbox.filesCreated || [],
                filesModified: sandbox.filesModified || [],
                filesDeleted: sandbox.filesDeleted || [],
                processesSpawned: sandbox.processesSpawned || [],
                networkAttempts: sandbox.networkAttempts || [],
                durationMs: sandbox.duration_ms ||
                    sandbox.durationMs ||
                    0,
                timedOut: sandbox.timedOut || false
            }
        };
    }
    catch (error) {
        // -------------------------------------------------------
        // API ERROR
        // -------------------------------------------------------
        console.error('[Vibe-Guard] API Error:', error);
        return {
            executionId: 'error',
            decision: 'WARN',
            finalRisk: 50,
            confidence: 0,
            staticRisk: 0,
            runtimeRisk: 0,
            aiRisk: 0,
            threats: [
                'API connection failed. Make sure the backend is running.'
            ],
            explanation: 'Could not connect to backend.',
            diagnostics: [],
            status: 'ERROR',
            aiEngine: 'Unavailable',
            llmInvoked: false,
            llmReason: 'Backend connection failed.',
            summary: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            },
            sandboxResult: {
                exitCode: 0,
                stdout: '',
                stderr: '',
                filesCreated: [],
                filesModified: [],
                filesDeleted: [],
                processesSpawned: [],
                networkAttempts: [],
                durationMs: 0,
                timedOut: false
            }
        };
    }
}
//# sourceMappingURL=client.js.map