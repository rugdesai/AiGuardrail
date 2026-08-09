import { FinalVerdict } from '../api/client';

export function getWebviewContent(isLoading: boolean, verdict?: FinalVerdict): string {
  const icon = {
    code: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>',
    search: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>',
    docker: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>',
    sparkles: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v18"></path><path d="M3 12h18"></path><path d="M15.5 8.5l-7 7"></path><path d="M8.5 8.5l7 7"></path></svg>',
    shield: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
    alert: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>',
    check: '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>',
    x: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'
  };

  let bodyContent = '';

  if (isLoading) {
    bodyContent =
      '<div class="timeline loading-timeline">' +
      '<div class="timeline-step">' +
      '<div class="step-dot">' + icon.code + '</div>' +
      '<div class="step-label">Code Input</div>' +
      '</div>' +
      '<div class="timeline-step">' +
      '<div class="step-dot">' + icon.search + '</div>' +
      '<div class="step-label">Static Analysis</div>' +
      '</div>' +
      '<div class="timeline-step">' +
      '<div class="step-dot">' + icon.docker + '</div>' +
      '<div class="step-label">Docker Sandbox</div>' +
      '</div>' +
      '<div class="timeline-step">' +
      '<div class="step-dot">' + icon.sparkles + '</div>' +
      '<div class="step-label">IBM Guardian</div>' +
      '</div>' +
      '<div class="timeline-step">' +
      '<div class="step-dot"><div class="spinner-mini"></div></div>' +
      '<div class="step-label">Verdict</div>' +
      '</div>' +
      '</div>' +
      '<div class="loading-state-body">' +
      '<div class="loading-text" style="text-align: center; margin-top: 40px; color: var(--text-dim); font-size: 14px; font-weight: 600;">Analyzing code safely...</div>' +
      '</div>';
  } else if (verdict) {
    const blockedClass = verdict.decision === 'BLOCK' ? 'blocked' : verdict.decision === 'WARN' ? 'warn' : 'done';
    const decisionIcon = verdict.decision === 'BLOCK' ? icon.x : verdict.decision === 'WARN' ? icon.alert : icon.check;
    
    const decisionText = verdict.decision === 'BLOCK' ? '❌ BLOCKED' 
      : verdict.decision === 'WARN' ? '⚠️ WARNING' 
      : '✅ ALLOWED';

    const riskScore = verdict.finalRisk ?? 0;

    let threatCardsHtml = '';
    if (verdict.threats && verdict.threats.length > 0) {
      threatCardsHtml = verdict.threats.map(threat =>
        '<div class="threat-card">' +
          '<div class="threat-icon">⚠️</div>' +
          '<div class="threat-content">' +
            '<div class="threat-title">' + threat + '</div>' +
          '</div>' +
        '</div>'
      ).join('');
    } else {
      threatCardsHtml = '<div style="color: var(--text-dim); font-size: 13px;">No active threats detected.</div>';
    }

    bodyContent =
      '<div class="timeline">' +
      '<div class="timeline-step done"><div class="step-dot">' + icon.code + '</div><div class="step-label">Code Input</div></div>' +
      '<div class="timeline-step done"><div class="step-dot">' + icon.search + '</div><div class="step-label">Static Analysis</div></div>' +
      '<div class="timeline-step done"><div class="step-dot">' + icon.docker + '</div><div class="step-label">Docker Sandbox</div></div>' +
      '<div class="timeline-step done"><div class="step-dot">' + icon.sparkles + '</div><div class="step-label">IBM Guardian</div></div>' +
      '<div class="timeline-step ' + blockedClass + '"><div class="step-dot">' + decisionIcon + '</div><div class="step-label">Verdict</div><div class="step-sublabel-badge">' + verdict.decision + '</div></div>' +
      '</div>' +

      '<div class="risk-section">' +
        '<div class="risk-meter-container">' +
          '<svg class="risk-meter-svg" width="100" height="100" viewBox="0 0 100 100">' +
            '<circle class="risk-meter-bg" cx="50" cy="50" r="40"></circle>' +
            '<circle class="risk-meter-fill" cx="50" cy="50" r="40" style="stroke: ' + (verdict.decision === "BLOCK" ? "#f5556c" : "#33d17a") + '; stroke-dasharray: 251.2; stroke-dashoffset: ' + (251.2 - (251.2 * riskScore) / 100) + '"></circle>' +
          '</svg>' +
          '<div class="risk-meter-text">' +
            '<div class="risk-score-num">' + riskScore + '</div>' +
            '<div class="risk-score-label">RISK</div>' +
          '</div>' +
        '</div>' +
        '<div class="risk-details">' +
          '<div class="decision-badge" style="color: ' + (verdict.decision === "BLOCK" ? "#f5556c" : "#33d17a") + '; border-color: ' + (verdict.decision === "BLOCK" ? "#f5556c40" : "#33d17a40") + '; background: ' + (verdict.decision === "BLOCK" ? "#f5556c11" : "#33d17a11") + ';">' +
            decisionText +
          '</div>' +
          '<div class="risk-breakdown">' +
             '<div class="sub-risk-row">' +
                '<div class="sub-risk-label">Static Risk: <strong>' + verdict.staticRisk + '</strong></div>' +
                '<div class="sub-risk-bar-bg"><div class="sub-risk-bar-fill" style="width: ' + verdict.staticRisk + '%; background: ' + (verdict.staticRisk >= 70 ? '#f5556c' : verdict.staticRisk >= 30 ? '#f6ad3d' : '#33d17a') + '"></div></div>' +
             '</div>' +
             '<div class="sub-risk-row">' +
                '<div class="sub-risk-label">Runtime Risk: <strong>' + verdict.runtimeRisk + '</strong></div>' +
                '<div class="sub-risk-bar-bg"><div class="sub-risk-bar-fill" style="width: ' + verdict.runtimeRisk + '%; background: ' + (verdict.runtimeRisk >= 70 ? '#f5556c' : verdict.runtimeRisk >= 30 ? '#f6ad3d' : '#33d17a') + '"></div></div>' +
             '</div>' +
             '<div class="sub-risk-row">' +
                '<div class="sub-risk-label">AI Risk: <strong>' + verdict.aiRisk + '</strong></div>' +
                '<div class="sub-risk-bar-bg"><div class="sub-risk-bar-fill" style="width: ' + verdict.aiRisk + '%; background: ' + (verdict.aiRisk >= 70 ? '#f5556c' : verdict.aiRisk >= 30 ? '#f6ad3d' : '#33d17a') + '"></div></div>' +
             '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="section-title">Detected Threats</div>' +
      '<div class="threat-list">' + threatCardsHtml + '</div>' +



      '<div class="guardian-card" style="margin-top: 30px;">' +
        '<div class="guardian-header">' +
          icon.sparkles + ' <span>IBM WatsonX Guardian Analysis</span>' +
        '</div>' +
        '<div class="guardian-body">' + verdict.explanation + '</div>' +
      '</div>' +

      '<div class="chat-container">' +
        '<div class="chat-header">Ask Bob (Security Copilot)</div>' +
        '<div class="chat-messages" id="chat-messages">' +
          '<div class="chat-msg bob">Hello! I noticed your code was blocked. Would you like me to suggest a safer alternative?</div>' +
        '</div>' +
        '<div class="chat-input-wrapper">' +
          '<input type="text" class="chat-input" id="chat-input" placeholder="Ask how to fix this...">' +
          '<button class="chat-btn" onclick="sendMessage()">Send</button>' +
        '</div>' +
      '</div>';
  }

  return `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8"/>
    <title>Vibe-Guard Report</title>
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }
      :root { --bg: #0b0d12; --panel: rgba(21, 24, 35, 0.7); --panel-2: #1b1f2d; --border: rgba(38, 43, 58, 0.8); --text: #e7e9ee; --text-dim: #8890a4; --accent: #7c8aff; }
      
      body { 
        font-family: -apple-system, "Segoe UI", sans-serif; 
        background: radial-gradient(circle at 0% 0%, rgba(124, 138, 255, 0.05) 0%, transparent 40%),
                    radial-gradient(circle at 100% 100%, rgba(245, 85, 108, 0.05) 0%, transparent 40%),
                    #0b0d12; 
        color: var(--text); 
        min-height: 100vh; 
        padding: 30px; 
      }
      
      .header { display: flex; align-items: center; gap: 14px; margin-bottom: 26px; padding-bottom: 18px; border-bottom: 1px solid var(--border); }
      .header-logo { width: 42px; height: 42px; border-radius: 12px; background: linear-gradient(135deg, #7c8aff, #b06cff); display: flex; align-items: center; justify-content: center; color: #0b0d12; box-shadow: 0 6px 18px -6px #7c8aff88; }
      .header-title { font-size: 19px; font-weight: 800; color: #fafbff; letter-spacing: -0.2px; }
      .header-subtitle { font-size: 12px; color: var(--text-dim); margin-top: 2px; }

      .timeline { display: flex; align-items: flex-start; margin-bottom: 26px; background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 22px; backdrop-filter: blur(10px); }
      .timeline-step { display: flex; flex-direction: column; align-items: center; flex: 1; position: relative; }
      .timeline-step:not(:last-child)::after { content: ""; position: absolute; right: -50%; top: 14px; width: 100%; height: 2px; background: var(--border); z-index: 0; }
      .timeline-step.done:not(:last-child)::after { background: linear-gradient(90deg, #33d17a, #33d17a88); }
      .step-dot { width: 30px; height: 30px; border-radius: 50%; background: var(--panel-2); border: 1px solid var(--border); display: flex; align-items: center; justify-content: center; font-size: 13px; z-index: 1; position: relative; color: var(--text-dim); transition: all 0.3s ease; }
      
      @keyframes stepLightUp { 0% { background: var(--panel-2); color: var(--text-dim); border-color: var(--border); } 100% { background: #33d17a; color: #06210f; border-color: #33d17a; } }
      @keyframes lineLightUp { 0% { background: var(--border); } 100% { background: linear-gradient(90deg, #33d17a, #33d17a88); } }
      @keyframes pulseDot { 0%, 100% { box-shadow: 0 0 0 0 rgba(124, 138, 255, 0); } 50% { box-shadow: 0 0 0 8px rgba(124, 138, 255, 0.2); } }
      
      .loading-timeline .timeline-step:nth-child(1) .step-dot { animation: stepLightUp 0.1s forwards; }
      .loading-timeline .timeline-step:nth-child(1)::after { animation: lineLightUp 0.1s 0.05s forwards; }
      .loading-timeline .timeline-step:nth-child(2) .step-dot { animation: stepLightUp 0.1s 0.3s forwards; }
      .loading-timeline .timeline-step:nth-child(2)::after { animation: lineLightUp 0.1s 0.35s forwards; }
      .loading-timeline .timeline-step:nth-child(3) .step-dot { animation: stepLightUp 0.1s 0.9s forwards; }
      .loading-timeline .timeline-step:nth-child(3)::after { animation: lineLightUp 0.1s 0.95s forwards; }
      .loading-timeline .timeline-step:nth-child(4) .step-dot { animation: stepLightUp 0.1s 1.5s forwards; }
      .loading-timeline .timeline-step:nth-child(4)::after { animation: lineLightUp 0.1s 1.55s forwards; }
      .loading-timeline .timeline-step:nth-child(5) .step-dot { animation: pulseDot 1s 2.0s infinite; border-color: var(--accent); color: var(--accent); }
      
      .spinner-mini { width: 14px; height: 14px; border: 2px solid var(--accent); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; }
      @keyframes spin { 100% { transform: rotate(360deg); } }

      .timeline-step.done .step-dot { background: #33d17a; border-color: #33d17a; color: #06210f; font-weight: 700; }
      .timeline-step.blocked .step-dot { background: #f5556c; border-color: #f5556c; color: #2a0007; font-weight: 700; }
      .timeline-step.warn .step-dot { background: #f6ad3d; border-color: #f6ad3d; color: #2a1a00; font-weight: 700; }
      .step-label { margin-top: 9px; font-size: 11px; color: var(--text-dim); text-align: center; font-weight: 700; letter-spacing: 0.2px; }
      .step-sublabel-badge { font-weight: 800; padding: 2px 7px; border-radius: 4px; font-size: 9px; margin-top: 6px; }
      .timeline-step.blocked .step-sublabel-badge { background: #f5556c22; color: #f5556c; border: 1px solid #f5556c40; }
      .timeline-step.done .step-sublabel-badge { background: #33d17a22; color: #33d17a; border: 1px solid #33d17a40; }
      .timeline-step.warn .step-sublabel-badge { background: #f6ad3d22; color: #f6ad3d; border: 1px solid #f6ad3d40; }
      .step-dot svg { display: block; }

      .risk-section { display: flex; align-items: center; gap: 30px; margin-bottom: 26px; background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 26px; backdrop-filter: blur(10px); }
      .risk-meter-container { position: relative; flex-shrink: 0; }
      .risk-meter-svg { transform: rotate(-90deg); }
      .risk-meter-bg { fill: none; stroke: var(--panel-2); stroke-width: 9; }
      .risk-meter-fill { fill: none; stroke-width: 9; stroke-linecap: round; transition: stroke-dashoffset 0.6s ease; }
      .risk-meter-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); text-align: center; }
      .risk-score-num { font-size: 34px; font-weight: 800; line-height: 1; }
      .risk-score-label { font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
      .risk-details { flex: 1; min-width: 0; }
      .decision-badge { display: inline-flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 800; margin-bottom: 16px; padding: 6px 16px; border-radius: 999px; border: 1px solid; }
      .risk-breakdown { display: flex; flex-direction: column; gap: 9px; }
      .sub-risk-row { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 2px; }
      .sub-risk-label { font-size: 13px; color: var(--text-dim); }
      .sub-risk-label strong { color: var(--text); }
      .sub-risk-bar-bg { width: 100px; height: 6px; background: rgba(255,255,255,0.05); border-radius: 3px; overflow: hidden; }
      .sub-risk-bar-fill { height: 100%; border-radius: 3px; }

      .section-title { font-size: 13px; font-weight: 700; color: var(--text); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; }
      
      .threat-list { display: flex; flex-direction: column; gap: 10px; }
      .threat-card { background: rgba(245, 85, 108, 0.05); border: 1px solid rgba(245, 85, 108, 0.2); padding: 14px; border-radius: 12px; display: flex; gap: 12px; align-items: flex-start; }
      .threat-icon { font-size: 16px; margin-top: 1px; }
      .threat-title { font-size: 13.5px; font-weight: 600; color: #ffd6dc; }

      .sandbox-card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; font-family: ui-monospace, monospace; font-size: 12px; color: var(--text-dim); margin-bottom: 26px; }
      .telemetry-row { margin-bottom: 8px; }
      .telemetry-row:last-child { margin-bottom: 0; }
      .telemetry-row span { color: var(--text); }

      .guardian-card { background: linear-gradient(145deg, rgba(124, 138, 255, 0.08), rgba(176, 108, 255, 0.03)); border: 1px solid rgba(124, 138, 255, 0.2); border-radius: 12px; padding: 18px; margin-bottom: 26px; }
      .guardian-header { display: flex; align-items: center; gap: 8px; font-weight: 700; color: #d6dbff; margin-bottom: 10px; font-size: 14px; }
      .guardian-body { font-size: 13.5px; line-height: 1.5; color: #a8b0cc; }

      .chat-container { background: var(--panel); border: 1px solid var(--border); border-radius: 16px; display: flex; flex-direction: column; height: 400px; overflow: hidden; }
      .chat-header { padding: 14px 18px; border-bottom: 1px solid var(--border); font-size: 13px; font-weight: 700; }
      .chat-messages { flex: 1; padding: 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; }
      .chat-msg { max-width: 85%; padding: 10px 14px; border-radius: 12px; font-size: 13px; line-height: 1.4; }
      .chat-msg.bob { background: rgba(124, 138, 255, 0.1); color: #d6dbff; align-self: flex-start; border-bottom-left-radius: 4px; }
      .chat-msg.user { background: var(--panel-2); color: var(--text); align-self: flex-end; border-bottom-right-radius: 4px; }
      .chat-input-wrapper { display: flex; padding: 12px; border-top: 1px solid var(--border); gap: 10px; background: rgba(0,0,0,0.2); }
      .chat-input { flex: 1; background: var(--panel-2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; color: var(--text); outline: none; }
      .chat-btn { background: var(--accent); color: #000; border: none; border-radius: 8px; padding: 0 16px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
      .chat-btn:hover { opacity: 0.9; }
    </style>
  </head>
  <body>
    <div class="header">
      <div class="header-logo">${icon.shield}</div>
      <div>
        <div class="header-title">Vibe-Guard Report</div>
        <div class="header-subtitle">Analysis powered by IBM WatsonX</div>
      </div>
    </div>
    
    ${bodyContent}

    <script>
      const vscode = acquireVsCodeApi();

      // Listen for Bob's reply coming back from the extension
      window.addEventListener("message", (event) => {
        const message = event.data;
        if (message.command === "bobReply") {
          const messages = document.getElementById("chat-messages");
          
          // Remove the "Thinking..." bubble
          const thinking = document.getElementById("bob-thinking");
          if (thinking) { thinking.remove(); }

          const bobMsg = document.createElement("div");
          bobMsg.className = "chat-msg bob";
          bobMsg.textContent = message.text;
          messages.appendChild(bobMsg);
          messages.scrollTop = messages.scrollHeight;
        }
      });

      function sendMessage() {
        const input = document.getElementById("chat-input");
        const text = input.value.trim();
        if(!text) return;
        
        const messages = document.getElementById("chat-messages");
        
        // Add user message
        const userMsg = document.createElement("div");
        userMsg.className = "chat-msg user";
        userMsg.textContent = text;
        messages.appendChild(userMsg);
        
        input.value = "";

        // Add "Thinking..." bubble
        const thinkingMsg = document.createElement("div");
        thinkingMsg.className = "chat-msg bob";
        thinkingMsg.id = "bob-thinking";
        thinkingMsg.textContent = "⏳ Thinking...";
        messages.appendChild(thinkingMsg);

        messages.scrollTop = messages.scrollHeight;
        
        // Send to the VS Code extension which will call WatsonX
        vscode.postMessage({ command: "askBob", text: text });
      }

      document.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && document.activeElement && document.activeElement.id === "chat-input") {
          sendMessage();
        }
      });
    </script>
  </body>
  </html>`;
}
