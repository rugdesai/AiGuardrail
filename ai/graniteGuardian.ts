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
    Analyze the following code.

    Source Code:
    ${sourceCode}

    Static Analysis Findings:
    ${JSON.stringify(staticFlags, null, 2)}

    Sandbox Execution:
    ${sandboxOutput}
    `;

    const rawResponse = await callWatsonX(
        GUARDIAN_SYSTEM_PROMPT,
        userPrompt
    );
    const cleanedResponse = rawResponse
        .replace(/```json/g, "")
        .replace(/```/g, "")
        .trim();

    const parsedResponse = JSON.parse(cleanedResponse);

    return GuardianResponseSchema.parse(parsedResponse);
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