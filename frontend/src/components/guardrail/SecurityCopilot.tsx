import { useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ArrowUp, Bot } from "lucide-react";
import { cn } from "@/lib/utils";
import { CodeBlock, SectionLabel } from "./primitives";
import { answerFor, securityReport } from "@/data/security-report";

interface Msg {
  id: number;
  role: "assistant" | "user";
  text: string;
}

const copilot = securityReport.copilot;

export function SecurityCopilot() {
  const [messages, setMessages] = useState<Msg[]>([
    { id: 0, role: "assistant", text: copilot.greeting },
  ]);
  const [input, setInput] = useState("");
  const [typing, setTyping] = useState(false);
  const idRef = useRef(1);

  const send = (question: string) => {
    const q = question.trim();
    if (!q || typing) return;
    setMessages((m) => [...m, { id: idRef.current++, role: "user", text: q }]);
    setInput("");
    setTyping(true);
    setTimeout(() => {
      setMessages((m) => [...m, { id: idRef.current++, role: "assistant", text: answerFor(q) }]);
      setTyping(false);
    }, 900);
  };

  return (
    <section id="copilot" className="px-3.5 py-3">
      <SectionLabel title="Copilot" meta={copilot.name} />

      <div className="panel flex flex-col overflow-hidden">
        {/* Bob lives in the chat header */}
        <div className="flex min-w-0 items-center gap-2 border-b border-border px-3 py-2.5">
          <span
            className="relative grid h-6 w-6 shrink-0 place-items-center rounded-lg"
            style={{ backgroundImage: "var(--gradient-kiwi)" }}
          >
            <Bot className="h-3.5 w-3.5 text-background" strokeWidth={2.4} />
          </span>
          <span className="min-w-0">
            <span className="flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-kiwi" />
              <span className="truncate font-display text-[0.75rem] font-bold tracking-tight">
                {copilot.name}
              </span>
            </span>
            <span className="label-xs block truncate text-[0.5rem]">{copilot.subtitle}</span>
          </span>
        </div>

        <div className="max-h-[260px] flex-1 space-y-2.5 overflow-y-auto p-3">
          <AnimatePresence initial={false}>
            {messages.map((m) => (
              <motion.div
                key={m.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}
              >
                <div
                  className={cn(
                    "max-w-[85%] rounded-xl px-2.5 py-2 text-[0.72rem] leading-relaxed",
                    m.role === "user"
                      ? "bg-foreground text-background"
                      : "bg-surface-2/60 text-foreground/90 ring-1 ring-border",
                  )}
                >
                  <RichText text={m.text} />
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          {typing ? (
            <div className="flex items-center gap-1 pl-1">
              {[0, 1, 2].map((i) => (
                <motion.span
                  key={i}
                  className="h-1 w-1 rounded-full bg-kiwi"
                  animate={{ opacity: [0.25, 1, 0.25], y: [0, -2, 0] }}
                  transition={{ duration: 1, repeat: Infinity, delay: i * 0.15 }}
                />
              ))}
            </div>
          ) : null}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            send(input);
          }}
          className="grid grid-cols-[minmax(0,1fr)_auto] gap-2 border-t border-border p-2"
        >
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={copilot.placeholder}
            aria-label="Ask Guardrail Copilot"
            className="min-w-0 rounded-lg bg-background/60 px-2.5 py-2 text-[0.72rem] outline-none ring-1 ring-border transition-shadow placeholder:text-muted-foreground/70 focus:ring-kiwi/50"
          />
          <button
            type="submit"
            className="inline-flex shrink-0 items-center gap-1 rounded-lg px-2.5 py-2 font-display text-[0.55rem] font-bold uppercase tracking-[0.16em] text-background transition-transform hover:-translate-y-0.5"
            style={{ backgroundImage: "var(--gradient-kiwi)" }}
          >
            Send <ArrowUp className="h-3 w-3" />
          </button>
        </form>
      </div>
    </section>
  );
}

function RichText({ text }: { text: string }) {
  const blocks = text.split(/```/);
  return (
    <div className="space-y-2">
      {blocks.map((block, i) =>
        i % 2 === 1 ? (
          <CodeBlock key={i} code={block.replace(/^[a-z]*\n/, "").trimEnd()} className="my-1.5" />
        ) : (
          <div key={i} className="space-y-1.5">
            {block
              .split("\n")
              .filter((l) => l.trim().length > 0)
              .map((line, j) => (
                <p key={j} className={cn(line.trim().startsWith("•") && "pl-1")}>
                  {inlineBold(line)}
                </p>
              ))}
          </div>
        ),
      )}
    </div>
  );
}

function inlineBold(line: string) {
  return line.split(/(\*\*[^*]+\*\*|`[^`]+`)/).map((chunk, i) => {
    if (chunk.startsWith("**")) {
      return (
        <strong key={i} className="font-display font-bold">
          {chunk.slice(2, -2)}
        </strong>
      );
    }
    if (chunk.startsWith("`")) {
      return (
        <code key={i} className="rounded bg-background/70 px-1 py-0.5 font-mono text-[0.9em]">
          {chunk.slice(1, -1)}
        </code>
      );
    }
    return <span key={i}>{chunk}</span>;
  });
}
