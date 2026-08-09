import { SectionLabel } from "./primitives";
import type { securityReport } from "@/data/security-report";

type Sandbox = typeof securityReport.sandbox;

export function SandboxTelemetry({ sandbox }: { sandbox: Sandbox }) {
  return (
    <section id="sandbox" className="px-3.5 py-3">
      <SectionLabel title="Sandbox" meta="telemetry" />

      <div className="panel divide-y divide-border overflow-hidden text-[0.72rem]">
        <div className="grid grid-cols-2 divide-x divide-border">
          <Row label="Exit code" value={<span className="text-kiwi">{sandbox.exitCode}</span>} />
          <Row label="Duration" value={<span className="text-yellow">{sandbox.duration}</span>} />
        </div>

        <div className="px-3 py-2.5">
          <div className="label-xs text-[0.52rem] text-red">Files deleted</div>
          <ul className="mt-1.5 space-y-0.5 font-mono text-[0.7rem] text-red/90">
            {sandbox.filesDeleted.map((f) => (
              <li key={f} className="truncate">
                {f}
              </li>
            ))}
          </ul>
        </div>

        <div className="px-3 py-2.5">
          <div className="label-xs text-[0.52rem] text-red">Processes spawned</div>
          <ul className="mt-1.5 space-y-0.5 font-mono text-[0.7rem] text-red/90">
            {sandbox.processes.map((p) => (
              <li key={p} className="truncate">
                {p}
              </li>
            ))}
          </ul>
        </div>

        <div className="px-3 py-2.5">
          <div className="label-xs text-[0.52rem]">Stdout</div>
          <div className="mt-1.5 font-mono text-[0.7rem] text-foreground/85">{sandbox.stdout}</div>
        </div>
      </div>
    </section>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2 px-3 py-2.5">
      <span className="label-xs text-[0.52rem]">{label}</span>
      <span className="num-display font-mono text-sm">{value}</span>
    </div>
  );
}
