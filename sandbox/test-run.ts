import { runSandbox } from "./run";

async function main() {
  const result = await runSandbox(
    `
import os

with open("pwned.txt", "w") as f:
    f.write("PWNED")

os.system("ls -la /")

print("MALICIOUS TEST COMPLETE")
`,
    "python"
  );

  console.log("\\n=== MALICIOUS TEST ===");
  console.log(result);
}

main();