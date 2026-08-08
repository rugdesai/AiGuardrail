import { motion } from "motion/react";
import { DataBar, SectionLabel, StatusBadge, useCountUp } from "./primitives";
import type { securityReport } from "@/data/security-report";

export function RiskOverview({
  report,
  active,
}: {
  report: typeof securityReport;
  active: boolean;
}) {
  const score = useCountUp(report.riskScore, active, 1200);
  const r = 26;
  const circumference = 2 * Math.PI * r;

  return (
    <section id="report" className="px-3.5 py-3">
      <SectionLabel title="Risk score" meta={report.language} />

      <div className="panel relative overflow-hidden p-3.5">
        <div
          aria-hidden
          className="pointer-events-none absolute -left-8 -top-10 h-32 w-32 rounded-full opacity-40"
          style={{ backgroundImage: "var(--gradient-danger)", filter: "blur(42px)" }}
        />
        <div className="relative flex items-center gap-3.5">
          <div className="relative h-[64px] w-[64px] shrink-0">
            <svg viewBox="0 0 64 64" className="h-full w-full -rotate-90">
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stopColor="oklch(0.58 0.24 26)" />
                  <stop offset="100%" stopColor="oklch(0.9 0.19 100)" />
                </linearGradient>
              </defs>
              <circle cx="32" cy="32" r={r} fill="none" stroke="oklch(1 0 0 / 9%)" strokeWidth="3" />
              <motion.circle
                cx="32"
                cy="32"
                r={r}
                fill="none"
                stroke="url(#riskGrad)"
                strokeWidth="3"
                strokeLinecap="round"
                strokeDasharray={circumference}
                initial={{ strokeDashoffset: circumference }}
                animate={{ strokeDashoffset: circumference * (1 - report.riskScore / 100) }}
                transition={{ duration: 1.4, ease: [0.16, 1, 0.3, 1] }}
              />
            </svg>
            <span className="absolute inset-0 grid place-items-center">
              <span className="num-display text-gradient-danger text-2xl">{score}</span>
            </span>
          </div>

          <div className="min-w-0 flex-1">
            <StatusBadge verdict={report.verdict} />
            <div className="mt-2.5 grid gap-1.5">
              <DataBar label="Static" value={report.scores.static} accent="kiwi" active={active} />
              <DataBar label="Runtime" value={report.scores.runtime} accent="danger" active={active} />
              <DataBar label="AI" value={report.scores.ai} accent="yellow" active={active} />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
