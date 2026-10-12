import { randomUUID } from "node:crypto";

import type { HostsDataset } from "./schema";
import type { NormalizedHost } from "./normalize";

export type DatasetSource = "sample" | "upload" | "api" | "other";

export interface StoredDatasetEntry {
  dataset: HostsDataset;
  normalized: NormalizedHost[];
  createdAt: number;
  source: DatasetSource;
  label?: string;
  ownerSessionId: string;
}

const DATASET_TTL_MS = 15 * 60 * 1000;
const MAX_ENTRIES = 24;

const datasetStore = new Map<string, StoredDatasetEntry>();

function pruneExpiredEntries(now: number): void {
  for (const [key, entry] of datasetStore) {
    if (now - entry.createdAt > DATASET_TTL_MS) {
      datasetStore.delete(key);
    }
  }
}

function pruneOverflow(): void {
  if (datasetStore.size <= MAX_ENTRIES) {
    return;
  }

  const entries = Array.from(datasetStore.entries()).sort(
    (a, b) => a[1].createdAt - b[1].createdAt,
  );

  while (entries.length > MAX_ENTRIES) {
    const [key] = entries.shift() ?? [];
    if (key) {
      datasetStore.delete(key);
    }
  }
}

export interface SaveDatasetOptions {
  dataset: HostsDataset;
  normalized: NormalizedHost[];
  source: DatasetSource;
  label?: string;
  ownerSessionId: string;
}

export function saveDataset({
  dataset,
  normalized,
  source,
  label,
  ownerSessionId,
}: SaveDatasetOptions): string {
  const now = Date.now();
  pruneExpiredEntries(now);
  pruneOverflow();

  const id = randomUUID();
  datasetStore.set(id, {
    dataset,
    normalized,
    createdAt: now,
    source,
    label,
    ownerSessionId,
  });

  return id;
}

export function getDataset(id: string): StoredDatasetEntry | null {
  const entry = datasetStore.get(id);
  if (!entry) {
    return null;
  }

  const now = Date.now();
  if (now - entry.createdAt > DATASET_TTL_MS) {
    datasetStore.delete(id);
    return null;
  }

  return entry;
}

export function getDatasetForSession(
  id: string,
  ownerSessionId: string,
): StoredDatasetEntry | null {
  const entry = getDataset(id);
  if (!entry || entry.ownerSessionId !== ownerSessionId) {
    return null;
  }

  return entry;
}

export function deleteDataset(id: string): void {
  datasetStore.delete(id);
}

export function clearDatasets(): void {
  datasetStore.clear();
}
