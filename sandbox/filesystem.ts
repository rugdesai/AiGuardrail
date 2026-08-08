import { readdir, stat } from "fs/promises";
import { join, relative } from "path";

export interface FileSnapshot {
  path: string;
  size: number;
  mtimeMs: number;
}

export async function snapshotDirectory(
  directory: string
): Promise<FileSnapshot[]> {
  const files: FileSnapshot[] = [];

  async function walk(currentDir: string) {
    const entries = await readdir(currentDir, {
      withFileTypes: true,
    });

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);

      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }

      const fileStats = await stat(fullPath);

      files.push({
        path: relative(directory, fullPath),
        size: fileStats.size,
        mtimeMs: fileStats.mtimeMs,
      });
    }
  }

  await walk(directory);

  return files;
}