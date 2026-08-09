import { callWatsonX } from "./watsonx.js";
import { BOB_SYSTEM_PROMPT } from "./prompts/bobSystemPrompt.js";

import type {
    GuardianResponse
} from "./graniteGuardian.js";

export interface ChatMessage {
    role: "user" | "assistant";
    content: string;
}

export async function askBob(

    question: string,

    guardianResult: GuardianResponse,

    history: ChatMessage[] = []

): Promise<string> {

    const conversation = history
    .map(
        message =>
            `${message.role.toUpperCase()}: ${message.content}`
    )
    .join("\n\n");

    const userPrompt = `
    Guardian Evaluation:

    ${JSON.stringify(guardianResult, null, 2)}

    Previous Conversation:

    ${conversation}

    Current User Question:

    ${question}

    Answer the current question while using both the Guardian evaluation and the previous conversation as context.

    If there is no previous conversation, simply answer the current question.
    `;

    const response = await callWatsonX(

        BOB_SYSTEM_PROMPT,

        userPrompt

    );

    return response.trim();
}