export function extractProcessNames(
  stdout: string,
  stderr: string
): string[] {
  const processes = new Set<string>();

  const combinedOutput = `${stdout}\n${stderr}`;

  const patterns = [
    /subprocess.*?\[['"]([^'"]+)['"]/g,
    /running\s+([a-zA-Z0-9_.-]+)/gi,
  ];

  for (const pattern of patterns) {
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(combinedOutput)) !== null) {
      processes.add(match[1]);
    }
  }

  return Array.from(processes);
}