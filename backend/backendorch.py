import os
from dotenv import load_dotenv

# This tells Python to load the secrets from the .env file!
load_dotenv()

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid
import httpx
import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Query

# 1. Initialize the AST Parser for C
C_LANGUAGE = Language(tsc.language(), 'c')
parser = Parser()
parser.set_language(C_LANGUAGE)

app = FastAPI(title="VibeGuard Orchestrator")
active_executions: Dict[str, dict] = {}


class CodePayload(BaseModel):
    language: str
    codeSnippet: str
    userPrompt: Optional[str] = None


class DiagnosticItem(BaseModel):
    type: str
    message: str
    lineStart: int
    lineEnd: int


# 2. The Deterministic AST Checker
def run_static_checks(code: str, language: str) -> List[DiagnosticItem]:
    diagnostics = []

    if language.lower() == "c":
        # Parse the raw code into a structural syntax tree
        tree = parser.parse(bytes(code, "utf8"))

        # We query the AST to find any typedef structs hiding a pointer
        # This enforces explicit pointer visibility (Way 2) over hidden typedefs.
        query = C_LANGUAGE.query("""
                    (type_definition
                        type: (struct_specifier)
                        declarator: (pointer_declarator) @hidden_pointer
                    )
                """)

        captures = query.captures(tree.root_node)

        for capture in captures:
            node = capture[0]
            diagnostics.append(
                DiagnosticItem(
                    type="CRITICAL",
                    message="Security Risk: Hidden pointer typedef detected. Keep pointer asterisks explicitly visible to prevent memory leaks.",
                    lineStart=node.start_point[0] + 1,
                    lineEnd=node.end_point[0] + 1
                )
            )

    return diagnostics

import httpx
import json


async def analyze_with_watsonx(code: str, prompt: str):
    try:
        # The base URL plus the specific text generation endpoint
        url = "https://eu-de.ml.cloud.ibm.com/ml/v1/text/generation?version=2023-05-29"

        headers = {
            "Authorization": os.getenv("IBM_BEARER_TOKEN"),
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        system_prompt = f"""
        You are a strict security auditor. Analyze this code against the user's request.
        User Request: {prompt}
        Code: {code}

        Return ONLY valid JSON in this exact format, with NO other text or markdown:
        {{"scope_drift_score": 0.0, "reason": "string"}}
        """

        payload = {
            "input": system_prompt,
            "model_id": "meta-llama/llama-3-3-70b-instruct",
            "project_id": os.getenv("IBM_PROJECT_ID"),
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": 200
            }
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, headers=headers, timeout=15.0)

            if response.status_code != 200:
                print(f"IBM API Error {response.status_code}: {response.text}")
                return {"scope_drift_score": 0.0, "reason": f"AI API HTTP {response.status_code}."}

            response_data = response.json()

            if 'results' not in response_data or not response_data['results']:
                return {"scope_drift_score": 0.0, "reason": "Empty AI response structure."}

            ai_text = response_data['results'][0].get('generated_text', '').strip()

            if not ai_text:
                return {"scope_drift_score": 0.0, "reason": "AI returned empty text."}

            # 1. Regex to find the first complete JSON dictionary
            import re
            match = re.search(r'\{.*?\}', ai_text, re.DOTALL)

            if match:
                clean_json_text = match.group(0)
                print(f"CLEANED AI TEXT: {clean_json_text}")
                try:
                    return json.loads(clean_json_text)
                except json.JSONDecodeError:
                    print("Failed to parse Llama-3 output into JSON.")
                    return {"scope_drift_score": 5.0, "reason": "AI returned malformed JSON."}
            else:
                # 2. If no JSON brackets exist at all, return a safe fallback dictionary
                print(f"AI returned text with no JSON brackets: {ai_text}")
                return {"scope_drift_score": 5.0, "reason": "AI failed to return JSON."}

    except Exception as e:
        print(f"AI Connection Failed: {e}")
        return {"scope_drift_score": 0.0, "reason": "AI analysis offline."}
import httpx


async def analyze_with_sandbox(code: str, language: str = "python"):
    try:
        # Live Pinggy tunnel routing straight to her port 3000
        # Permanent ngrok tunnel to her Mac
        sandbox_url = "https://sniff-worrisome-stipulate.ngrok-free.dev/run-sandbox"

        # Bypasses the ngrok free-tier warning screen


        payload = {
            "code": code,
            "language": language
        }

        # Bypasses the Pinggy HTML warning screen
        headers = {
            "ngrok-skip-browser-warning": "true"
        }

        async with httpx.AsyncClient() as client:
            # 15s timeout to allow Docker container spin-up time
            response = await client.post(sandbox_url, json=payload, headers=headers, timeout=15.0)

            if response.status_code == 200:
                data = response.json()

                risk_score = 0.0
                reason = "Sandbox execution safe."

                # Check for network attempts (returns {} if empty based on telemetry)
                network_attempts = data.get("networkAttempts", {})
                if network_attempts and len(network_attempts) > 0:
                    risk_score = 9.0
                    reason = "Malicious network activity detected in sandbox."
                elif data.get("exitCode", 0) != 0:
                    risk_score = 5.0
                    reason = f"Runtime error: {data.get('stderr', 'Execution failed.')}"

                return {
                    "sandbox_risk_score": risk_score,
                    "reason": reason,
                    "stdout": data.get("stdout", ""),
                    "duration_ms": data.get("durationMs", 0),
                    # --- ADD THESE THREE LINES ---
                    "networkAttempts": data.get("networkAttempts", []),
                    "filesCreated": data.get("filesCreated", []),
                    "processesSpawned": data.get("processesSpawned", [])
                }
            else:
                return {"sandbox_risk_score": 0.0, "reason": f"Sandbox HTTP Error: {response.status_code}"}

    except Exception as e:
        print(f"Sandbox Error: {e}")
        return {"sandbox_risk_score": 0.0, "reason": "Sandbox offline or timed out."}

@app.post("/analyze")
async def analyze_code(payload: CodePayload):
    import uuid
    import asyncio
    exec_id = f"run_{uuid.uuid4().hex[:8]}"

    # 1. Run the lightning-fast deterministic AST checks
    static_results = run_static_checks(payload.codeSnippet, payload.language)

    # 2. Run the AI and the Sandbox AT THE SAME TIME (Asynchronous magic)
    user_prompt = payload.userPrompt if payload.userPrompt else "Write safe code."

    # asyncio.gather runs both network requests simultaneously so the IDE doesn't lag
    ai_results, sandbox_results = await asyncio.gather(
        analyze_with_watsonx(payload.codeSnippet, user_prompt),
        analyze_with_sandbox(payload.codeSnippet, payload.language)
    )

    # 3. Compile Diagnostics (Squiggles)
    if ai_results.get("scope_drift_score", 0) > 5.0:
        static_results.append(
            DiagnosticItem(
                type="SCOPE_DRIFT",
                message=f"AI Warning: {ai_results.get('reason', 'Scope drift detected.')}",
                lineStart=1,
                lineEnd=1
            )
        )

# --- NEW TELEMETRY CHECKS ---
    # 1. Penalize Network Calls
    if len(sandbox_results.get("networkAttempts", [])) > 0:
        static_results.append(
            DiagnosticItem(
                type="CRITICAL",
                message=f"Sandbox Alert: Malicious network activity detected {sandbox_results['networkAttempts']}.",
                lineStart=1,
                lineEnd=1
            )
        )

    # 2. Penalize File Creation
    if len(sandbox_results.get("filesCreated", [])) > 0:
        static_results.append(
            DiagnosticItem(
                type="CRITICAL",
                message=f"Sandbox Alert: Unauthorized file creation detected {sandbox_results['filesCreated']}.",
                lineStart=1,
                lineEnd=1
            )
        )

    # 3. Penalize Shell Execution
    if len(sandbox_results.get("processesSpawned", [])) > 0:
        static_results.append(
            DiagnosticItem(
                type="CRITICAL",
                message=f"Sandbox Alert: Unauthorized shell execution detected {sandbox_results['processesSpawned']}.",
                lineStart=1,
                lineEnd=1
            )
        )

    # --- EXISTING SCORE CHECK ---
    if sandbox_results.get("sandbox_risk_score", 0) > 7.0:
        static_results.append(
            DiagnosticItem(
                type="CRITICAL",
                message=f"Sandbox Alert: {sandbox_results.get('reason', 'Malicious runtime behavior detected.')}",
                lineStart=1,
                lineEnd=1
            )
        )

    # 4. Final Math Engine
    # If the AST catches hidden pointers OR Sandbox catches malicious behavior, base score is CRITICAL
    has_critical = any(d.type == "CRITICAL" for d in static_results)
    base_score = 8.5 if has_critical else 0.0

    # Add the AI's scope drift penalty
    final_score = base_score + (ai_results.get("scope_drift_score", 0) / 10.0)

    return {
        "executionId": exec_id,
        "finalRiskScore": min(final_score, 10.0),
        "diagnostics": static_results
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backendorch:app", host="127.0.0.1", port=8000, reload=True)