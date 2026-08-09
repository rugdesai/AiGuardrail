import { motion } from "motion/react";
import { Box, Code2, Search, ShieldAlert, Sparkles, Check, X, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { SectionLabel } from "./primitives";
import type { StageStatus } from "./types";

const icons = { code: Code2, search: Search, box: Box, sparkles: Sparkles, shield: ShieldAlert };

export interface Stage {
  num: string;
  title: string;
  icon: keyof typeof icons;
}

const dotStyle: Record<StageStatus, string> = {
  pending: "bg-surface-2 ring-border text-muted-foreground/60",
  active: "ring-yellow/50 text-background",
  complete: "ring-kiwi/50 text-background",
  failed: "ring-red/60 text-background",
};

const labelStyle: Record<StageStatus, string> = {
  pending: "text-muted-foreground/50",
  active: "text-yellow",
  complete: "text-kiwi",
  failed: "text-red",
};

const short: Record<string, string> = {
  "Code Input": "Code",
  "Static Analysis": "Static",
  "Docker Sandbox": "Docker",
  "IBM Guardian": "IBM",
  Verdict: "Verdict",
};

export function AnalysisPipeline({
  stages,
  statuses,
}: {
  stages: Stage[];
  statuses: StageStatus[];
}) {
  return (
    <section id="pipeline" className="px-3.5 py-3">
      <SectionLabel title="Pipeline" meta="05 stages" />

      <div className="relative flex items-start justify-between">
        {/* base line */}
        <span className="absolute left-3 right-3 top-[9px] h-px bg-border" />
        {stages.map((stage, i) => {
          const status = statuses[i] ?? "pending";
          const Icon = icons[stage.icon];
          const grad =
            status === "failed"
              ? "var(--gradient-danger)"
              : status === "active"
                ? "var(--gradient-yellow)"
                : "var(--gradient-kiwi)";
          const filled = status !== "pending";
          return (
            <div key={stage.num} className="relative z-10 flex min-w-0 flex-1 flex-col items-center">
              {i < stages.length - 1 && filled ? (
                <motion.span
                  aria-hidden
                  initial={{ scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.5, delay: i * 0.08, ease: "easeInOut" }}
                  className="absolute left-1/2 top-[9px] h-px w-full origin-left"
                  style={{ backgroundImage: grad }}
                />
              ) : null}

              <span
                className={cn(
                  "relative grid h-[18px] w-[18px] place-items-center rounded-full ring-1",
                  dotStyle[status],
                )}
                style={filled ? { backgroundImage: grad } : undefined}
              >
                {status === "active" ? (
                  <span
                    className="absolute inset-0 rounded-full animate-pulse-ring"
                    style={{ backgroundImage: grad }}
                  />
                ) : null}
                <span className="relative">
                  {status === "complete" ? (
                    <Check className="h-2.5 w-2.5" strokeWidth={3.5} />
                  ) : status === "failed" ? (
                    <X className="h-2.5 w-2.5" strokeWidth={3.5} />
                  ) : status === "active" ? (
                    <Loader2 className="h-2.5 w-2.5 animate-spin" />
                  ) : (
                    <Icon className="h-2.5 w-2.5" />
                  )}
                </span>
              </span>

              <span className="mt-1.5 font-mono text-[0.5rem] text-muted-foreground/60">
                {stage.num}
              </span>
              <span
                className={cn(
                  "mt-0.5 max-w-full truncate font-display text-[0.55rem] font-bold uppercase tracking-[0.08em]",
                  labelStyle[status],
                )}
              >
                {short[stage.title] ?? stage.title}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
