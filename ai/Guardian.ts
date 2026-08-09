import axios from "axios";
import { z } from "zod";
import { callWatsonX } from "./watsonx.js";
import { GUARDIAN_SYSTEM_PROMPT } from "./prompts/guardianPrompt.js";

const GuardianResponseSchema = z.object({
    riskScore: z.number().min(0).max(100),
    riskLevel: z.enum(["LOW", "MEDIUM", "HIGH"]),
    confidence: z.number().min(0).max(1),
    threats: z.array(z.string()),
    explanation: z.string(),
    recommendation: z.string(),
});

export type GuardianResponse = z.infer<typeof GuardianResponseSchema>;

export async function evaluateWithGuardian(
    sourceCode: string,
    staticFlags: string[],
    sandboxOutput: string
): Promise<GuardianResponse> {
try{
const userPrompt = `
Analyze ONLY the following submission.

Return EXACTLY ONE JSON object.

Source Code:
${sourceCode}

Static Analysis Findings:
${JSON.stringify(staticFlags, null, 2)}

Sandbox Execution:
${sandboxOutput}

Do not analyze any other examples.
Do not generate multiple answers.
Return one JSON object only.
`;

    const rawResponse = await callWatsonX(
        GUARDIAN_SYSTEM_PROMPT,
        userPrompt
    );

const cleaned = rawResponse
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();

let depth = 0;
let start = -1;
let end = -1;

for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i];

    if (ch === "{") {
        if (depth === 0) start = i;
        depth++;
    } else if (ch === "}") {
        depth--;

        if (depth === 0) {
            end = i;
            break;
        }
    }
}

if (start === -1 || end === -1) {
    throw new Error("Could not find a valid JSON object.");
}

const jsonString = cleaned.substring(start, end + 1);

console.log("Extracted JSON:");
console.log(jsonString);

const parsed = JSON.parse(jsonString);

return GuardianResponseSchema.parse(parsed);
}catch(error){
    console.error("Guardian evaluation failed:", error);
    return {
        riskScore: 100,
        riskLevel: "HIGH",
        confidence: 0,
        threats: [
            "Guardian evaluation failed"
        ],
        explanation:
            "The AI could not safely analyze this submission.",     
        recommendation:
            "Review this code manually before allowing execution."
    };
 }
}