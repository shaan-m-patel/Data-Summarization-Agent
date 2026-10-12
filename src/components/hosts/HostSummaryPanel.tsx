"use client";

import { useMemo, useState, useTransition } from "react";
import styled from "styled-components";

import { summaryConflictsWithRecord } from "@/lib/summaryTrust";
import { summarizeHost } from "@/server/actions/summarizeHost";
import type { NormalizedHost } from "@/server/normalize";

const STORED_DATASET_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type SummaryStatus = "idle" | "loading" | "success" | "error";

interface SummaryState {
  status: SummaryStatus;
  result?: Awaited<ReturnType<typeof summarizeHost>>;
}

const initialState: SummaryState = {
  status: "idle",
};

export function HostSummaryPanel({
  host,
  datasetId,
}: {
  host: NormalizedHost;
  datasetId?: string;
}) {
  const [state, setState] = useState<SummaryState>(initialState);
  const [isPending, startTransition] = useTransition();
  const canSummarize = Boolean(datasetId && STORED_DATASET_ID.test(datasetId));

  const hasResult = state.status === "success" || state.status === "error";
  const showError =
    state.status === "error" && state.result && state.result.errorKind !== "none";

  const highlights = useMemo(() => state.result?.highlights ?? [], [state.result]);
  const risks = useMemo(() => state.result?.risks ?? [], [state.result]);
  const conflicts = useMemo(() => {
    if (!state.result) {
      return false;
    }
    return summaryConflictsWithRecord(host, state.result);
  }, [host, state.result]);
  const topCves = host.vulnerabilities.top.slice(0, 3).map((vuln) => vuln.cveId);

  const handleSummarize = () => {
    if (!datasetId || !canSummarize) {
      return;
    }
    startTransition(async () => {
      setState({ status: "loading", result: state.result });
      const result = await summarizeHost({ datasetId, ip: host.ip });
      setState({
        status: result.errorKind === "none" ? "success" : "error",
        result,
      });
    });
  };

  const buttonLabel = (() => {
    if (isPending || state.status === "loading") {
      return "Summarizing…";
    }
    if (state.status === "success") {
      return "Summarize again";
    }
    if (state.status === "error") {
      return "Retry summary";
    }
    return "Summarize host";
  })();

  return (
    <Panel>
      <PanelHeader>
        <div>
          <PanelEyebrow>LLM summary</PanelEyebrow>
          <PanelTitle>Generate triage highlights</PanelTitle>
        </div>
        <SummarizeButton
          type="button"
          onClick={handleSummarize}
          disabled={isPending || !canSummarize}
        >
          {buttonLabel}
        </SummarizeButton>
      </PanelHeader>

      {!canSummarize && (
        <EmptyState>
          Summaries run only for a dataset stored in your session. Open the sample or
          upload a file from the home page, then summarize from that result.
        </EmptyState>
      )}

      {canSummarize && state.status === "idle" && (
        <EmptyState>
          Run a server-side summary to review prioritized actions, scoped to this host’s
          stored telemetry. CVE and risk figures on this page stay authoritative if the
          model text disagrees.
        </EmptyState>
      )}

      {state.status === "loading" && (
        <SkeletonGroup role="status" aria-live="polite">
          <SkeletonLine style={{ width: "70%" }} />
          <SkeletonLine style={{ width: "54%" }} />
          <SkeletonLine style={{ width: "88%" }} />
        </SkeletonGroup>
      )}

      {hasResult && (
        <SummaryContent>
          <RecordedFindings data-testid="recorded-findings">
            <SectionHeading>Recorded findings</SectionHeading>
            <RecordedNote>
              These values come from the stored dataset. Use them as the primary triage
              when the model summary disagrees.
            </RecordedNote>
            <List>
              <li>Risk badge: {host.riskBadge.label}</li>
              <li>
                Vulnerabilities: {host.vulnerabilities.total} (max{" "}
                {host.vulnerabilities.maxSeverity})
              </li>
              <li>
                Top CVEs: {topCves.length > 0 ? topCves.join(", ") : "none recorded"}
              </li>
            </List>
          </RecordedFindings>

          {conflicts && (
            <ConflictBanner role="alert" data-testid="summary-conflict">
              This model summary conflicts with the stored record. The vulnerability table
              and risk badge are the primary triage. Treat the text below as untrusted
              model output.
            </ConflictBanner>
          )}

          <SummarySection $muted={conflicts}>
            <SectionHeading>Model highlights</SectionHeading>
            {highlights.length === 0 ? (
              <Placeholder>No model highlights returned.</Placeholder>
            ) : (
              <List>
                {highlights.map((highlight) => (
                  <li key={highlight}>{highlight}</li>
                ))}
              </List>
            )}
          </SummarySection>

          <SummarySection $muted={conflicts}>
            <SectionHeading>Model risks</SectionHeading>
            {risks.length === 0 ? (
              <Placeholder>No model risks returned.</Placeholder>
            ) : (
              <List>
                {risks.map((risk) => (
                  <li key={risk}>{risk}</li>
                ))}
              </List>
            )}
          </SummarySection>

          <SummarySection $muted={conflicts}>
            <SectionHeading>Model narrative</SectionHeading>
            <Narrative>{state.result?.narrative}</Narrative>
          </SummarySection>

          {showError && (
            <ErrorBanner role="alert">
              {state.result?.errorMessage ??
                "Summarization fell back to cached heuristics."}
            </ErrorBanner>
          )}
        </SummaryContent>
      )}
    </Panel>
  );
}

const Panel = styled.section`
  display: flex;
  flex-direction: column;
  gap: ${({ theme }) => theme.spacing(3)};
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: ${({ theme }) => theme.radius.lg};
  padding: ${({ theme }) => theme.spacing(4)};
  box-shadow: ${({ theme }) => theme.shadow.sm};
`;

const PanelHeader = styled.header`
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: ${({ theme }) => theme.spacing(3)};
  flex-wrap: wrap;
`;

const PanelEyebrow = styled.p`
  margin: 0;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  font-size: 0.75rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.textMuted};
`;

const PanelTitle = styled.h2`
  margin: ${({ theme }) => theme.spacing(1)} 0 0;
  font-size: 1.35rem;
  color: ${({ theme }) => theme.colors.textPrimary};
`;

const SummarizeButton = styled.button`
  display: inline-flex;
  align-items: center;
  gap: ${({ theme }) => theme.spacing(2)};
  border: none;
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.primary};
  color: ${({ theme }) => theme.colors.accentContrast};
  font-weight: 600;
  padding: ${({ theme }) => theme.spacing(2.75)} ${({ theme }) => theme.spacing(4.5)};
  cursor: pointer;
  transition:
    transform 0.2s ease,
    box-shadow 0.2s ease,
    background 0.2s ease;
  font-size: 0.95rem;
  letter-spacing: 0.01em;

  &:disabled {
    opacity: 0.6;
    cursor: progress;
  }

  &:focus-visible {
    outline: 3px solid ${({ theme }) => theme.colors.focus};
    outline-offset: 2px;
  }

  &:hover:not(:disabled) {
    transform: translateY(-1px);
    box-shadow: 0 10px 20px rgba(44, 79, 94, 0.25);
    background: ${({ theme }) => theme.colors.primaryDark};
  }
`;

const EmptyState = styled.p`
  margin: 0;
  line-height: 1.6;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const SkeletonGroup = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(2)};
`;

const SkeletonLine = styled.span`
  display: block;
  height: 0.9rem;
  border-radius: 999px;
  background: linear-gradient(
    90deg,
    rgba(219, 234, 254, 0.35) 0%,
    rgba(148, 163, 184, 0.4) 50%,
    rgba(219, 234, 254, 0.35) 100%
  );
  background-size: 200% 100%;
  animation: shimmer 1.4s infinite;

  @keyframes shimmer {
    0% {
      background-position: 200% 0;
    }
    100% {
      background-position: -200% 0;
    }
  }
`;

const SummaryContent = styled.div`
  display: grid;
  gap: ${({ theme }) => theme.spacing(4)};
`;

const RecordedFindings = styled.section`
  display: grid;
  gap: ${({ theme }) => theme.spacing(2)};
  padding: ${({ theme }) => theme.spacing(3)};
  border-radius: ${({ theme }) => theme.radius.md};
  border: 1px solid ${({ theme }) => theme.colors.primary};
  background: ${({ theme }) => theme.colors.surfaceMuted};
`;

const RecordedNote = styled.p`
  margin: 0;
  line-height: 1.5;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const ConflictBanner = styled.div`
  border-left: 4px solid ${({ theme }) => theme.colors.danger};
  background: rgba(220, 38, 38, 0.08);
  padding: ${({ theme }) => theme.spacing(2.5)};
  border-radius: ${({ theme }) => theme.radius.md};
  color: ${({ theme }) => theme.colors.textPrimary};
  line-height: 1.5;
`;

const SummarySection = styled.section<{ $muted?: boolean }>`
  display: grid;
  gap: ${({ theme }) => theme.spacing(2)};
  opacity: ${({ $muted }) => ($muted ? 0.72 : 1)};
`;

const SectionHeading = styled.h3`
  margin: 0;
  font-size: 1.1rem;
  color: ${({ theme }) => theme.colors.textPrimary};
`;

const List = styled.ul`
  margin: 0;
  padding-left: ${({ theme }) => theme.spacing(4)};
  display: grid;
  gap: ${({ theme }) => theme.spacing(1.5)};
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const Narrative = styled.p`
  margin: 0;
  line-height: 1.6;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const Placeholder = styled.p`
  margin: 0;
  color: ${({ theme }) => theme.colors.textMuted};
`;

const ErrorBanner = styled.div`
  border-left: 4px solid ${({ theme }) => theme.colors.warning};
  background: ${({ theme }) => theme.colors.accentSoft};
  padding: ${({ theme }) => theme.spacing(2.5)};
  border-radius: ${({ theme }) => theme.radius.md};
  color: ${({ theme }) => theme.colors.textPrimary};
`;
