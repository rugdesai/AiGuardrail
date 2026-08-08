import { runSandbox } from "./run";

async function main() {
  const result = await runSandbox(
    `
import os
import subprocess
import socket

# Create a file
with open("malicious.txt", "w") as f:
    f.write("suspicious content")

# Spawn a process
subprocess.run(["ls", "-la"])

# Attempt network access
try:
    socket.create_connection(("example.com", 80), timeout=2)
except Exception:
    print("NETWORK BLOCKED")

# Delete the file
os.remove("malicious.txt")

print("ATTACK TEST COMPLETE")
`,
    "python"
  );

  console.log("\\n=== FINAL ATTACK TEST ===");
  console.log(result);
}

main();