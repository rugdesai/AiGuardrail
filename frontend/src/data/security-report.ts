export type Severity = "CRITICAL" | "HIGH" | "WARNING" | "INFO";
export type Verdict = "BLOCKED" | "REVIEW" | "SAFE" | "SCANNING";

export interface Threat {
  id: string;
  index: string;
  title: string;
  severity: Severity;
  description: string;
  evidence: string;
}

export const securityReport = {
  language: "Python",
  riskScore: 91,
  verdict: "BLOCKED" as Verdict,
  scores: {
    static: 70,
    runtime: 95,
    ai: 90,
  },
  pipeline: [
    {
      num: "01",
      title: "Code Input",
      icon: "code" as const,
    },
    {
      num: "02",
      title: "Static Analysis",
      icon: "search" as const,
    },
    {
      num: "03",
      title: "Docker Sandbox",
      icon: "box" as const,
    },
    {
      num: "04",
      title: "IBM Guardian",
      icon: "sparkles" as const,
    },
    {
      num: "05",
      title: "Verdict",
      icon: "shield" as const,
    },
  ],
  threats: [
    {
      id: "t1",
      index: "01",
      title: "Destructive filesystem operation",
      severity: "CRITICAL",
      description:
        "The submitted code recursively deletes files from the filesystem via a shell command.",
      evidence: `os.system("rm -rf /tmp/data")`,
    },
  ] as Threat[],
  sandbox: {
    exitCode: 0,
    duration: "450ms",
    filesDeleted: ["/tmp/data/file1.txt", "/tmp/data/file2.txt"],
    processes: ["rm -rf /tmp/data"],
    stdout: "Deleting files...",
  },
  guardian: {
    model: "Granite Guardian",
    vendor: "IBM",
    explanation:
      "The script invokes a recursive delete via os.system('rm -rf'), confirmed by sandbox telemetry to have deleted files inside the container.",
  },
  copilot: {
    name: "Bob",
    subtitle: "Security Copilot · powered by IBM",
    greeting:
      "Hi! I've reviewed the security analysis. Ask me why this was flagged, or how to fix it.",
    placeholder: 'Ask Bob: "Why was this blocked?"',
  },
};

export const copilotAnswers: { match: string; answer: string }[] = [
  {
    match: "block",
    answer: `This code was blocked because it performs a **recursive filesystem deletion**.

Inside the sandbox the program executed \`rm -rf /tmp/data\` and deleted files in the container.

This behavior is classified as a **destructive filesystem operation**.`,
  },
  {
    match: "sandbox",
    answer: `Inside the isolated container the program ran for **450ms** and exited with code **0**.

• Files deleted — /tmp/data/file1.txt, /tmp/data/file2.txt
• Processes spawned — \`rm -rf /tmp/data\`
• Stdout — "Deleting files..."`,
  },
  {
    match: "fix",
    answer: `Drop \`os.system\` and never build shell strings for deletion.

Safer version:
\`\`\`python
from pathlib import Path

ALLOWED = Path("/workspace/scratch")

def cleanup(target: Path) -> None:
    target = target.resolve()
    if not target.is_relative_to(ALLOWED):
        raise PermissionError("destructive operation refused")
    for f in target.iterdir():
        f.unlink()
\`\`\``,
  },
];

export function answerFor(question: string): string {
  const q = question.toLowerCase();
  const hit = copilotAnswers.find((a) => q.includes(a.match));
  return (
    hit?.answer ??
    `This report ends in a **BLOCKED** verdict with a risk score of **91** — static 70, runtime 95, AI 90.

Ask me why this was blocked, what happened in the sandbox, or how to fix it.`
  );
}
