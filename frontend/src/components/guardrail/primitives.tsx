import { type ReactNode, useEffect, useRef, useState } from "react";
import { motion, useInView } from "motion/react";
import { Check, Copy } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Severity, Verdict } from "@/data/security-report";

/* ---------- ambient gradient objects ---------- */

export function GradientOrb({
  className,
  variant = "kiwi",
  size = 260,
}: {
  className?: string;
  variant?: "kiwi" | "yellow" | "mix" | "danger";
  size?: number;
}) {
  const bg: Record<string, string> = {
    kiwi: "var(--gradient-kiwi)",
    yellow: "var(--gradient-yellow)",
    mix: "var(--gradient-mix)",
    danger: "var(--gradient-danger)",
  };
  return (
    <div
      aria-hidden
      className={cn("orb animate-drift", className)}
      style={{ backgroundImage: bg[variant], width: size, height: size }}
    />
  );
}

export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });
  return (
    <motion.div
      ref={ref}
      className={className}
      initial={{ opacity: 0, y: 10 }}
      animate={inView ? { opacity: 1, y: 0 } : { opacity: 0, y: 10 }}
      transition={{ duration: 0.5, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  );
}

/* ---------- compact section label ---------- */

export function SectionLabel({
  title,
  meta,
  className,
}: {
  title: string;
  meta?: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 pb-2",
        className,
      )}
    >
      <span className="label-xs min-w-0 truncate text-[0.58rem] text-foreground/70">{title}</span>
      {meta ? (
        <span className="shrink-0 font-mono text-[0.6rem] text-muted-foreground">{meta}</span>
      ) : null}
    </div>
  );
}

/* ---------- severity + status ---------- */

export const severityStyles: Record<Severity, { text: string; bg: string; ring: string; bar: string }> = {
  CRITICAL: { text: "text-red", bg: "bg-red/12", ring: "ring-red/35", bar: "bg-red" },
  HIGH: {
    text: "text-red-bright",
    bg: "bg-red-bright/12",
    ring: "ring-red-bright/35",
    bar: "bg-red-bright",
  },
  WARNING: { text: "text-yellow", bg: "bg-yellow/12", ring: "ring-yellow/30", bar: "bg-yellow" },
  INFO: { text: "text-yellow", bg: "bg-yellow/12", ring: "ring-yellow/30", bar: "bg-yellow" },
};

export function SeverityTag({ severity, className }: { severity: Severity; className?: string }) {
  const s = severityStyles[severity];
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1.5 rounded-full px-1.5 py-0.5 font-display text-[0.5rem] font-bold uppercase tracking-[0.14em] ring-1",
        s.text,
        s.bg,
        s.ring,
        className,
      )}
    >
      <span className={cn("h-1 w-1 rounded-full", s.bar)} />
      {severity}
    </span>
  );
}

const verdictMap: Record<Verdict, { label: string; text: string; bg: string; ring: string }> = {
  SAFE: { label: "SAFE", text: "text-kiwi", bg: "bg-kiwi/12", ring: "ring-kiwi/40" },
  REVIEW: { label: "REVIEW", text: "text-yellow", bg: "bg-yellow/12", ring: "ring-yellow/40" },
  BLOCKED: { label: "BLOCKED", text: "text-red", bg: "bg-red/14", ring: "ring-red/45" },
  SCANNING: { label: "SCANNING", text: "text-kiwi", bg: "bg-kiwi/12", ring: "ring-kiwi/40" },
};

export function StatusBadge({ verdict, className }: { verdict: Verdict; className?: string }) {
  const v = verdictMap[verdict];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-1 font-display text-[0.6rem] font-bold uppercase tracking-[0.16em] ring-1",
        v.text,
        v.bg,
        v.ring,
        className,
      )}
    >
      <span className="relative flex h-1.5 w-1.5 shrink-0">
        <span className="absolute inset-0 rounded-full bg-current animate-pulse-ring" />
        <span className="h-1.5 w-1.5 rounded-full bg-current" />
      </span>
      {v.label}
    </span>
  );
}

/* ---------- count up ---------- */

export function useCountUp(target: number, active = true, duration = 1100) {
  const [value, setValue] = useState(active ? 0 : target);
  useEffect(() => {
    if (!active) return;
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration);
      setValue(Math.round(target * (1 - Math.pow(1 - p, 3))));
      if (p < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, active, duration]);
  return value;
}

/* ---------- code block ---------- */

export function CodeBlock({
  code,
  language,
  className,
  copy = true,
}: {
  code: string;
  language?: string;
  className?: string;
  copy?: boolean;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg bg-background/70 ring-1 ring-border",
        className,
      )}
    >
      {copy ? (
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard?.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 1600);
          }}
          className="absolute right-1 top-1 grid h-6 w-6 place-items-center rounded-md bg-surface-2/80 text-muted-foreground ring-1 ring-border transition-colors hover:text-foreground"
          aria-label="Copy code"
        >
          {copied ? <Check className="h-3 w-3 text-kiwi" /> : <Copy className="h-3 w-3" />}
        </button>
      ) : null}
      {language ? <div className="label-xs px-2.5 pt-2 text-[0.55rem]">{language}</div> : null}
      <pre className="overflow-x-auto px-2.5 py-2 pr-9 font-mono text-[0.7rem] leading-relaxed text-foreground/85">
        <code>{code}</code>
      </pre>
    </div>
  );
}

/* ---------- data bar ---------- */

export function DataBar({
  label,
  value,
  accent,
  active = true,
}: {
  label: string;
  value: number;
  accent: "kiwi" | "danger" | "yellow";
  active?: boolean;
}) {
  const grad: Record<string, string> = {
    kiwi: "var(--gradient-kiwi)",
    danger: "var(--gradient-danger)",
    yellow: "var(--gradient-yellow)",
  };
  const shown = useCountUp(value, active);
  return (
    <div className="grid grid-cols-[3.6rem_minmax(0,1fr)_1.6rem] items-center gap-2.5">
      <span className="label-xs text-[0.52rem]">{label}</span>
      <span className="h-[2px] w-full overflow-hidden rounded-full bg-foreground/10">
        <motion.span
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
          className="block h-full rounded-full"
          style={{ backgroundImage: grad[accent] }}
        />
      </span>
      <span className="num-display text-right font-mono text-[0.7rem] tabular-nums">{shown}</span>
    </div>
  );
}
