import { getDataset } from "./datasetStore";
import { loadNormalizedHosts } from "./loader";
import type { DatasetSource } from "./datasetStore";
import type { NormalizedHost } from "./normalize";

export interface ResolvedDataset {
  datasetId: string;
  source: DatasetSource;
  label: string;
  notice?: string;
  hosts: NormalizedHost[];
  isFallback: boolean;
}

export function readDatasetParam(
  value: string | string[] | undefined,
): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value ?? undefined;
}

export async function resolveDatasetSelection(
  datasetParam: string | undefined,
): Promise<ResolvedDataset> {
  if (!datasetParam || datasetParam === "sample") {
    const hosts = await loadNormalizedHosts();
    return {
      datasetId: "sample",
      source: "sample",
      label: "Bundled sample dataset",
      hosts,
      notice: undefined,
      isFallback: false,
    };
  }

  const stored = getDataset(datasetParam);
  if (!stored) {
    const hosts = await loadNormalizedHosts();
    return {
      datasetId: "sample",
      source: "sample",
      label: "Bundled sample dataset",
      hosts,
      notice:
        "The requested dataset was not found or has expired. Showing the bundled sample instead.",
      isFallback: true,
    };
  }

  const hosts = stored.normalized;
  const label = deriveDatasetLabel(
    stored.label,
    stored.source,
    stored.dataset.metadata.description,
  );

  return {
    datasetId: datasetParam,
    source: stored.source,
    label,
    hosts,
    notice: buildDatasetNotice(stored.source),
    isFallback: false,
  };
}

function deriveDatasetLabel(
  label: string | undefined,
  source: DatasetSource,
  fallbackDescription: string,
): string {
  const trimmedLabel = label?.trim();
  if (trimmedLabel) {
    return trimmedLabel;
  }
  if (fallbackDescription?.trim()) {
    return fallbackDescription.trim();
  }
  switch (source) {
    case "upload":
      return "Uploaded dataset";
    case "api":
      return "API dataset";
    default:
      return "Selected dataset";
  }
}

function buildDatasetNotice(source: DatasetSource): string | undefined {
  if (source === "upload") {
    return "Uploaded datasets remain cached in-memory for 15 minutes to support navigation.";
  }
  if (source === "api") {
    return "API datasets are cached for this session only.";
  }
  if (source === "sample") {
    return undefined;
  }
  return "Dataset ready. Explore risk indicators below.";
}
