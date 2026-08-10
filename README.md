# VibeGuard AI

AI-powered code security analysis directly inside Visual Studio Code.

VibeGuard AI analyzes source code using static analysis, sandbox execution, risk scoring, and AI-assisted security analysis to identify potential vulnerabilities before they reach production.

## Features

- Static security analysis
- Runtime sandbox analysis
- Vulnerability detection
- Risk scoring
- Security verdicts
- AI-assisted security analysis
- CWE and OWASP classification
- Confidence scoring
- Evidence and affected code locations
- Remediation recommendations
- Dependency analysis
- Secret detection
- Integrated VS Code security report

## How It Works

VibeGuard AI uses a layered security analysis pipeline:

                    VS Code Extension
                           |
                           v
                    Analysis Client
                           |
                           v
                      Backend API
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
   Static Analyzer      Sandbox       AI Analysis
          |                |                |
          +----------------+----------------+
                           |
                           v
                    Risk Aggregation
                           |
                           v
                    Security Verdict
                           |
                           v
                    VS Code Report

(images/img1.png)
(images/img2.png)
(images/img3.png)
(images/img4.png)