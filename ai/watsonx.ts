import axios from "axios";
import { getAccessToken } from "./auth.js";

const PROJECT_ID = process.env.WATSONX_PROJECT_ID!;
const BASE_URL = process.env.WATSONX_URL!;

export async function callWatsonX(
    systemPrompt: string,
    userPrompt: string
): Promise<string> {

    const token = await getAccessToken();
    const response = await axios.post(
        `${BASE_URL}/ml/v1/text/generation?version=2023-05-29`,
        {
            input: `${systemPrompt}\n\n${userPrompt}`,

            model_id: "ibm/granite-3-3-8b-instruct",

            project_id: PROJECT_ID,

            parameters: {
                decoding_method: "greedy",
                max_new_tokens: 1024,
                temperature: 0,
            },
        },
        {
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        }
        
    );
    return response.data.results[0].generated_text;
}