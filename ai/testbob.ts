import dotenv from "dotenv";
import { askBob } from "./bob.js";
import type { GuardianResponse } from "./Guardian.js";

dotenv.config({
    path: "./backend/.env",
});

async function main() {

    const guardianResult: GuardianResponse = {
        riskScore: 9,
        riskLevel: "HIGH",
        confidence: 0.9,
        threats: [
            "Code Injection",
            "Arbitrary Code Execution"
        ],
        explanation:
            "The use of eval() with user input allows arbitrary code execution.",
        recommendation:
            "Avoid eval() and use input validation."
    };

    const reply = await askBob(
        "Is this code safe to run?",
        guardianResult
    );

    console.log("========== BOB ==========");
    console.log(reply);
}

main();