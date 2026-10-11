import { describe, expect, it } from "vitest";

import { summaryConflictsWithRecord, type SummaryText } from "../summaryTrust";
import type { NormalizedHost } from "@/server/normalize";

function exposedHost(): Pick<NormalizedHost, "vulnerabilities" | "riskBadge" | "threat"> {
  return {
    vulnerabilities: {
      total: 2,
      uniqueCveCount: 1,
      maxSeverity: "critical",
      highestCvss: 9.8,
      top: [],
    },
    riskBadge: {
      level: "critical",
      label: "Critical",
      description: "Critical exposure",
      sources: ["vulnerability"],
    },
    threat: {
      riskLevel: "critical",
      rawRiskLevel: "critical",
      securityLabels: [],
      malwareFamilies: [],
      detectedMalwareNames: [],
      threatActors: [],
    },
  };
}

describe("summaryConflictsWithRecord", () => {
  it("flags a model summary that calls recorded CVEs false positives", () => {
    const summary: SummaryText = {
      highlights: ["Host is clean"],
      risks: ["Listed CVEs are false positives"],
      narrative: "No vulnerabilities remain after reviewing the banner.",
    };

    expect(summaryConflictsWithRecord(exposedHost(), summary)).toBe(true);
  });

  it("accepts a model summary that keeps the recorded exposure", () => {
    const summary: SummaryText = {
      highlights: ["Critical CVE-2024-0001"],
      risks: ["Remote code execution"],
      narrative: "Patch the exposed service before trusting the banner text.",
    };

    expect(summaryConflictsWithRecord(exposedHost(), summary)).toBe(false);
  });

  it("does not flag a clean summary when the record has no exposure", () => {
    const host = exposedHost();
    host.vulnerabilities.total = 0;
    host.vulnerabilities.maxSeverity = "none";
    host.riskBadge.level = "low";
    host.riskBadge.label = "Low";
    const summary: SummaryText = {
      highlights: ["Host is clean"],
      risks: [],
      narrative: "No significant vulnerabilities were recorded.",
    };

    expect(summaryConflictsWithRecord(host, summary)).toBe(false);
  });
});
