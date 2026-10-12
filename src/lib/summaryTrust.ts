import type { NormalizedHost } from "@/server/normalize";

export interface SummaryText {
  highlights: string[];
  risks: string[];
  narrative: string;
}

const CLEAN_CLAIM =
  /\b(?:(?:these|the|listed|all)\s+cves?\s+are\s+false\s+positives|false\s+positives?\s+only|host\s+is\s+(?:clean|safe|secure)|no\s+(?:known\s+|significant\s+|major\s+)?vulnerabilit(?:y|ies)|no\s+(?:significant\s+|major\s+|real\s+)?risks?\b|not\s+vulnerable|safe\s+to\s+ignore|ignore\s+(?:the\s+|these\s+|all\s+)?(?:cves?|vulnerabilit(?:y|ies)))\b/i;

export function recordShowsExposure(
  host: Pick<NormalizedHost, "vulnerabilities" | "riskBadge" | "threat">,
): boolean {
  return (
    host.vulnerabilities.total > 0 ||
    host.riskBadge.level === "critical" ||
    host.riskBadge.level === "high" ||
    host.riskBadge.level === "medium" ||
    host.threat.detectedMalwareNames.length > 0 ||
    host.threat.malwareFamilies.length > 0
  );
}

export function summaryConflictsWithRecord(
  host: Pick<NormalizedHost, "vulnerabilities" | "riskBadge" | "threat">,
  summary: SummaryText,
): boolean {
  if (!recordShowsExposure(host)) {
    return false;
  }

  const text = [...summary.highlights, ...summary.risks, summary.narrative].join("\n");
  return CLEAN_CLAIM.test(text);
}
