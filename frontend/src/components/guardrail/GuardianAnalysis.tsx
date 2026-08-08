import { SectionLabel } from "./primitives";
import type { securityReport } from "@/data/security-report";

export function GuardianAnalysis({ guardian }: { guardian: typeof securityReport.guardian }) {
  return (
    <section id="guardian" className="px-3.5 py-3">
      <SectionLabel title="Granite Guardian" meta={guardian.vendor} />

      <div className="panel relative overflow-hidden p-3.5">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-8 -top-10 h-28 w-28 rounded-full opacity-30"
          style={{ backgroundImage: "var(--gradient-mix)", filter: "blur(40px)" }}
        />
        <div className="relative flex min-w-0 flex-wrap items-center gap-2">
          <span className="rounded bg-ibm/20 px-1.5 py-0.5 font-display text-[0.55rem] font-bold tracking-[0.14em] text-ibm ring-1 ring-ibm/40">
            {guardian.vendor}
          </span>
          <span className="label-xs text-[0.52rem] text-ibm">
            Evaluated by {guardian.model}
          </span>
        </div>
        <p className="relative mt-2.5 text-[0.75rem] leading-relaxed text-foreground/85">
          {guardian.explanation}
        </p>
      </div>
    </section>
  );
}
