import dotenv from "dotenv";
import { evaluateWithGuardian } from "./Guardian.js";

dotenv.config({
    path: "./backend/.env",
});

async function main() {
    const result = await evaluateWithGuardian(
        `
        function login(password){
            eval(password);
        }
        `,
        [
            "Use of eval() detected",
            "Possible code injection"
        ],
        "Program executed successfully."
    );

    console.log("Guardian Result:");
    console.dir(result, { depth: null });
}

main();