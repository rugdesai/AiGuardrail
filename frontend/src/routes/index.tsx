import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Navigation } from "@/components/guardrail/Navigation";
import { AnalysisPipeline } from "@/components/guardrail/AnalysisPipeline";
import { RiskOverview } from "@/components/guardrail/RiskOverview";
import { ThreatList } from "@/components/guardrail/ThreatList";
import { SandboxTelemetry } from "@/components/guardrail/SandboxTelemetry";
import { GuardianAnalysis } from "@/components/guardrail/GuardianAnalysis";
import { SecurityCopilot } from "@/components/guardrail/SecurityCopilot";
import { GradientOrb, Reveal } from "@/components/guardrail/primitives";
import type { StageStatus } from "@/components/guardrail/types";
import { securityReport } from "@/data/security-report";

const title = "AI Guardrail — AI-Generated Code Security Report";
const description =
  "AI Guardrail analyzes AI-generated code with static analysis, an isolated Docker sandbox and Granite Guardian evaluation before it can safely execute.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title },
      { name: "description", content: description },
      { property: "og:title", content: title },
      { property: "og:description", content: description },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const finalStatuses: StageStatus[] = ["complete", "complete", "complete", "complete", "failed"];

function Index() {
  const [stage, setStage] = useState(0);

  useEffect(() => {
    const timers = securityReport.pipeline.map((_, i) =>
      setTimeout(() => setStage(i + 1), 500 * (i + 1)),
    );
    return () => timers.forEach(clearTimeout);
  }, []);

  const done = stage >= securityReport.pipeline.length;

  const statuses: StageStatus[] = done
    ? finalStatuses
    : securityReport.pipeline.map((_, i) =>
        i < stage ? (i === 4 ? "failed" : "complete") : i === stage ? "active" : "pending",
      );

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-mesh">
      <GradientOrb variant="danger" size={220} className="-left-16 top-24 opacity-25" />
      <GradientOrb variant="mix" size={200} className="-right-16 top-[55%] opacity-[0.16]" />

      <div className="relative mx-auto w-full max-w-[440px] border-x border-border/60">
        <Navigation />

        <main className="divide-y divide-border/60 pb-4">
          <AnalysisPipeline stages={securityReport.pipeline} statuses={statuses} />

          <RiskOverview report={securityReport} active={done} />

          <Reveal>
            <ThreatList threats={securityReport.threats} />
          </Reveal>

          <Reveal>
            <SandboxTelemetry sandbox={securityReport.sandbox} />
          </Reveal>

          <Reveal>
            <GuardianAnalysis guardian={securityReport.guardian} />
          </Reveal>

          <SecurityCopilot />
        </main>
      </div>
    </div>
  );
}
