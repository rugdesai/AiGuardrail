import { spawn } from "child_process";
import { randomUUID } from "crypto";
import { mkdtemp, writeFile, rm, readFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { snapshotDirectory } from "./filesystem";

export interface SandboxResult {
  executionId: string;

  exitCode: number | null;

  stdout: string;
  stderr: string;

  // These will be populated in Session 3.
  filesCreated: string[];
  filesModified: string[];
  filesDeleted: string[];

  processesSpawned: string[];
  networkAttempts: string[];

  durationMs: number;
  timedOut: boolean;
}

export async function runSandbox(
  code: string,
  language: "python"
): Promise<SandboxResult> {

  if (language !== "python") {
    throw new Error(`Unsupported language: ${language}`);
  }

  const executionId = randomUUID();
  const startTime = Date.now();

  // Create a unique temporary directory on the host.
  const tempDir = await mkdtemp(
    join(tmpdir(), `vibeguard-${executionId}-`)
  );

  const scriptPath = join(tempDir, "script.py");

  let stdout = "";
  let stderr = "";

  try {
    // Write the submitted code into script.py.
    await writeFile(scriptPath, code, "utf8");

    const telemetryRunnerPath = join(
  tempDir,
  "telemetry_runner.py"
);

await writeFile(
  telemetryRunnerPath,
  await readFile(
    join(process.cwd(), "telemetry_runner.py"),
    "utf8"
  ),
  "utf8"
);

    await writeFile(
        join(tempDir, "existing.txt"),
        "ORIGINAL CONTENT",
        "utf8"
    );

    const beforeSnapshot = await snapshotDirectory(tempDir);

    const dockerArgs = [
  "run",
  "--rm",

  // Network isolation
  "--network",
  "none",

  // Read-only container filesystem
  "--read-only",

  // Resource limits
  "--memory",
  "128m",

  "--cpus",
  "0.5",

  "--pids-limit",
  "64",

  // Writable temporary workspace
  "-v",
  `${tempDir}:/code`,

  "vibeguard-python",

  "python3",
  "/code/telemetry_runner.py",
  "/code/script.py",
];

    let timedOut = false;

const exitCode = await new Promise<number | null>(
  (resolve, reject) => {

    const DOCKER_BIN =
      process.env.DOCKER_BIN || "/usr/local/bin/docker";

    const child = spawn(DOCKER_BIN, dockerArgs);

    const timeout = setTimeout(() => {
      timedOut = true;

      child.kill("SIGKILL");

      resolve(null);
    }, 5000);

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);

      if (!timedOut) {
        resolve(code);
      }
    });
  }
);

    const afterSnapshot = await snapshotDirectory(tempDir);

    let processesSpawned: string[] = [];
let networkAttempts: string[] = [];

const telemetryMarker = "__VIBEGUARD_TELEMETRY__";

const telemetryIndex = stdout.lastIndexOf(telemetryMarker);

if (telemetryIndex !== -1) {
  const telemetryJson = stdout
    .slice(telemetryIndex + telemetryMarker.length)
    .trim();

  try {
    const telemetry = JSON.parse(telemetryJson);

    if (Array.isArray(telemetry.processesSpawned)) {
      processesSpawned = telemetry.processesSpawned;
    }

    if (Array.isArray(telemetry.networkAttempts)) {
      networkAttempts = telemetry.networkAttempts;
    }
  } catch {
    // Ignore malformed telemetry.
  }

  stdout = stdout.slice(0, telemetryIndex).trimEnd() + "\n";
}

    const beforeMap = new Map(
  beforeSnapshot.map((file) => [file.path, file])
);

const afterMap = new Map(
  afterSnapshot.map((file) => [file.path, file])
);

const filesCreated: string[] = [];
const filesModified: string[] = [];
const filesDeleted: string[] = [];

for (const file of afterSnapshot) {
  const before = beforeMap.get(file.path);

  if (!before) {
    filesCreated.push(file.path);
  } else if (
    before.size !== file.size ||
    before.mtimeMs !== file.mtimeMs
  ) {
    filesModified.push(file.path);
  }
}

for (const file of beforeSnapshot) {
  if (!afterMap.has(file.path)) {
    filesDeleted.push(file.path);
  }
}

    const durationMs = Date.now() - startTime;

    return {
      executionId,
      exitCode,

      stdout,
      stderr,

      filesCreated,
      filesModified,
      filesDeleted,

      processesSpawned,
      networkAttempts,

      durationMs,
      timedOut,
    };

  } finally {
    // ALWAYS delete the temporary host directory.
    await rm(tempDir, {
      recursive: true,
      force: true,
    });
  }
}