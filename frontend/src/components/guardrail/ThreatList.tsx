import { useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { CodeBlock, SectionLabel, SeverityTag, severityStyles } from "./primitives";
import type { Threat } from "@/data/security-report";

export function ThreatList({ threats }: { threats: Threat[] }) {
  const [openId, setOpenId] = useState<string | null>(null);

  return (
    <section id="threats" className="px-3.5 py-3">
      <SectionLabel
        title="Threats"
        meta={`· ${String(threats.length).padStart(2, "0")}`}
      />

      <div className="panel divide-y divide-border overflow-hidden">
        {threats.map((t) => {
          const open = openId === t.id;
          const s = severityStyles[t.severity];
          return (
            <div key={t.id} className="relative">
              <span
                className={cn(
                  "absolute inset-y-0 left-0 w-[2px] transition-opacity",
                  s.bar,
                  open ? "opacity-100" : "opacity-40",
                )}
              />
              <button
                type="button"
                onClick={() => setOpenId(open ? null : t.id)}
                aria-expanded={open}
                className="grid w-full grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-2 px-3 py-2.5 text-left transition-colors hover:bg-foreground/[0.03]"
              >
                <span className="font-mono text-[0.6rem] text-muted-foreground/60">{t.index}</span>
                <span className="min-w-0 truncate text-[0.8rem] font-medium leading-snug text-foreground/90">
                  {t.title}
                </span>
                <SeverityTag severity={t.severity} />
                <ChevronRight
                  className={cn(
                    "h-3 w-3 shrink-0 text-muted-foreground transition-transform",
                    open && "rotate-90",
                  )}
                />
              </button>

              <AnimatePresence initial={false}>
                {open ? (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                    className="overflow-hidden"
                  >
                    <div className="px-3 pb-3 pl-7">
                      <p className="text-[0.72rem] leading-relaxed text-muted-foreground">
                        {t.description}
                      </p>
                      <div className="label-xs mt-2.5 text-[0.52rem]">Evidence</div>
                      <CodeBlock code={t.evidence} className="mt-1.5" />
                    </div>
                  </motion.div>
                ) : null}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </section>
  );
}
