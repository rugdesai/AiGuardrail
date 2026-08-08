import dotenv from "dotenv";
import { callWatsonX } from "./watsonx.js";

dotenv.config({
    path: "./backend/.env",
});
console.log(process.env.WATSONX_PROJECT_ID);
console.log(process.env.WATSONX_URL);

async function main() {
    try {
        const response = await callWatsonX(
            "You are a helpful assistant.",
            'Reply with exactly this text: Hello AI Guardrail'
        );

        console.log("Model Response:");
        console.log(response);
    } catch (error: any) {
    console.error("WatsonX Test Failed:");

    if (error.response) {
        console.log("Status:", error.response.status);
        console.log("Data:");
        console.dir(error.response.data, { depth: null });
    } else {
        console.error(error);
    }
}
}

main();