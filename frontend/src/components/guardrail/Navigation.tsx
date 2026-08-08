import { Shield, MoreVertical } from "lucide-react";

export function Navigation() {
  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/85 backdrop-blur-xl">
      <div className="mx-auto grid max-w-[440px] grid-cols-[minmax(0,1fr)_auto] items-center gap-3 px-3.5 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className="grid h-5 w-5 shrink-0 place-items-center rounded-md"
            style={{ backgroundImage: "var(--gradient-kiwi)" }}
          >
            <Shield className="h-3 w-3 text-background" strokeWidth={2.6} />
          </span>
          <span className="truncate font-display text-[0.72rem] font-bold tracking-tight">
            AI Guardrail
          </span>
          <span className="hidden truncate text-[0.55rem] uppercase tracking-[0.18em] text-muted-foreground sm:block">
            · Code Security
          </span>
        </div>
        <MoreVertical className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      </div>
    </header>
  );
}
