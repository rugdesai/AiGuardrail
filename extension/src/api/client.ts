export interface Diagnostic {
  id?: string;
  type?: string;
  message?: string;
  lineStart?: number;
  lineEnd?: number;
  severity?: string;
  confidence?: number;
  cwe?: string;
  owasp?: string;
  source?: string[];
  evidence?: string;
  attackPath?: string[];
  remediation?: string;
  fixedCode?: string | null;
}

export interface FinalVerdict {
  executionId: string;

  decision: 'ALLOW' | 'BLOCK' | 'WARN';

  finalRisk: number;
  confidence: number;

  staticRisk: number;
  runtimeRisk: number;
  aiRisk: number;

  threats: string[];
  explanation: string;

  status?: string;
  aiEngine?: string;
  llmInvoked?: boolean;
  llmReason?: string;

  summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };

  diagnostics?: Array<{
    id?: string;
    type?: string;
    message?: string;
    lineStart?: number;
    lineEnd?: number;
    severity?: string;
    confidence?: number;
    cwe?: string;
    owasp?: string;
    source?: string[];
    evidence?: string;
    attackPath?: string[];
    remediation?: string;
    fixedCode?: string | null;
  }>;

  sandbox?: {
    available: boolean;
    sandboxRiskScore: number;
    reason?: string;
    networkAttempts?: string[];
    filesCreated?: string[];
    processesSpawned?: string[];
    duration_ms?: number;
  };

  analyzers?: {
    static?: boolean;
    semgrep?: boolean;
    secrets?: boolean;
    sandbox?: boolean;
    dependencyCheck?: boolean;
    llm?: boolean;
  };

  correlation?: {
    multiSourceFindings?: number;
    confirmedFindings?: any[];
  };

  sandboxResult: {
    exitCode: number;
    stdout: string;
    stderr: string;
    filesCreated: string[];
    filesModified: string[];
    filesDeleted: string[];
    processesSpawned: string[];
    networkAttempts: string[];
    durationMs: number;
    timedOut: boolean;
  };
}


export async function analyzeCode(
  code: string,
  language: string
): Promise<FinalVerdict> {
  const API_URL = "http://10.66.75.148:8000/analyze";

  console.log(`[Vibe-Guard] Analyzing ${language} code...`);
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
      throw new Error(
        `Backend returned HTTP ${response.status}`
      );
    }


    const data = await response.json();

    // --- Map status to decision ---
    const statusMap: Record<string, 'ALLOW' | 'WARN' | 'BLOCK'> = {
      'CRITICAL': 'BLOCK',
      'HIGH':     'BLOCK',
      'MEDIUM':   'WARN',
      'LOW':      'ALLOW',
      'SAFE':     'ALLOW',
    };
    const decision: 'ALLOW' | 'WARN' | 'BLOCK' =
      statusMap[data.status?.toUpperCase()] ??
      (data.finalRiskScore >= 7.5 ? 'BLOCK' : data.finalRiskScore >= 3.0 ? 'WARN' : 'ALLOW');

    // --- Scale risk scores to 0-100 ---
    const finalRisk   = Math.round((data.finalRiskScore || 0) * 10);
    const runtimeRisk = Math.round((data.sandbox?.sandbox_risk_score || 0) * 10);

    // Static risk: derived from summary counts
    const summary = data.summary || {};
    const staticRisk = Math.min(100, ((summary.critical || 0) * 30) + ((summary.high || 0) * 15) + ((summary.medium || 0) * 7) + ((summary.low || 0) * 2));

    // AI risk: use finalRisk as proxy when LLM was invoked
    const aiRisk = data.llmInvoked ? finalRisk : 0;

    // --- Build rich threat list: message + CWE/OWASP ---
    const diagnostics: any[] = data.diagnostics || [];
    const extractedThreats = diagnostics.map((d: any) => {
      let label = d.message || 'Unknown threat';
      if (d.cwe) { label += ` [${d.cwe}]`; }
      if (d.owasp) { label += ` — ${d.owasp}`; }
      return label;
    });

    // --- Build explanation from diagnostics ---
    let explanation = '';
    if (diagnostics.length === 0) {
      explanation = `Code scanned by ${data.aiEngine || 'AI'}. No threats detected. Safe to run.`;
    } else {
      const lines = diagnostics.map((d: any) => {
        let line = `• ${d.message}`;
        if (d.lineStart) { line += ` (line ${d.lineStart})`; }
        if (d.remediation) { line += `. Fix: ${d.remediation}`; }
        return line;
      });
      explanation = `Detected ${diagnostics.length} issue(s) via ${data.aiEngine || 'AI'}:\n${lines.join('\n')}`;
    }

    // --- Sandbox telemetry ---
    const sandbox = data.sandbox || {};

    return {
      executionId:  data.executionId || ('run_' + Date.now()),
      decision,
      finalRisk,
      confidence:   diagnostics[0]?.confidence ?? 0.9,
      staticRisk,
      runtimeRisk,
      aiRisk,
      threats:      extractedThreats,
      explanation,
      sandboxResult: {
        exitCode:         0,
        stdout:           '',
        stderr:           sandbox.reason || '',
        filesCreated:     sandbox.filesCreated     || [],
        filesModified:    [],
        filesDeleted:     [],
        processesSpawned: sandbox.processesSpawned || [],
        networkAttempts:  sandbox.networkAttempts  || [],
        durationMs:       sandbox.duration_ms      || 0,
        timedOut:         false,
      }
    };

  } catch (error) {
    console.error('[Vibe-Guard] API Error:', error);
    return {
      executionId:  'error',
      decision:     'WARN',
      finalRisk:    50,
      confidence:   0,
      staticRisk:   0,
      runtimeRisk:  0,
      aiRisk:       0,
      threats:      ['Could not connect to backend. Make sure the server is running.'],
      explanation:  'Could not connect to backend.',
      sandboxResult: { exitCode: 0, stdout: '', stderr: '', filesCreated: [], filesModified: [], filesDeleted: [], processesSpawned: [], networkAttempts: [], durationMs: 0, timedOut: false }
    };
  }
}