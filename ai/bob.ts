import { callWatsonX } from "./watsonx.js";
import { BOB_SYSTEM_PROMPT } from "./prompts/bobSystemPrompt.js";

import type {
    GuardianResponse
} from "./graniteGuardian.js";

export async function askBob(

    question: string,

    guardianResult: GuardianResponse

): Promise<string> {

    const userPrompt = `
Guardian Evaluation:

${JSON.stringify(guardianResult, null, 2)}

User Question:

${question}
`;

    const response = await callWatsonX(

        BOB_SYSTEM_PROMPT,

        userPrompt

    );

    return response.trim();
}