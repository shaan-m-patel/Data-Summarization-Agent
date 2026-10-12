"use server";

import "server-only";

import { z } from "zod";

import { getDatasetForSession } from "../datasetStore";
import type { NormalizedHost } from "../normalize";
import { readSession } from "../session";
import { SUMMARIZE_MAX_CONCURRENCY } from "../summarizeGuard";

import { summarizeHost } from "./summarizeHost";

const summarizeAllInputSchema = z
  .object({
    datasetId: z.string().uuid(),
    ips: z.array(z.string().trim().min(1).max(128)).max(24).optional(),
  })
  .strict();

export interface SummarizeAllRequest {
  datasetId: string;
  ips?: string[];
}

export interface SummarizeAllOptions {
  concurrency?: number;
  signal?: AbortSignal;
}

export interface SummarizeAllItemResult {
  index: number;
  host: NormalizedHost;
  result: Awaited<ReturnType<typeof summarizeHost>>;
}

export async function* summarizeAll(
  request: SummarizeAllRequest,
  options: SummarizeAllOptions = {},
): AsyncGenerator<SummarizeAllItemResult> {
  const parsed = summarizeAllInputSchema.safeParse(request);
  if (!parsed.success) {
    return;
  }

  const session = await readSession();
  if (!session) {
    return;
  }

  const stored = getDatasetForSession(parsed.data.datasetId, session.id);
  if (!stored) {
    return;
  }

  const requested = parsed.data.ips;
  const hosts = stored.normalized
    .filter((host) => (requested ? requested.includes(host.ip) : true))
    .slice(0, 24);
  if (hosts.length === 0) {
    return;
  }

  const concurrency = Math.max(
    1,
    Math.min(
      options.concurrency ?? SUMMARIZE_MAX_CONCURRENCY,
      SUMMARIZE_MAX_CONCURRENCY,
      hosts.length,
    ),
  );
  const queue = hosts.map((host, index) => ({ host, index }));
  let cursor = 0;
  const inFlight: Array<{ index: number; promise: Promise<SummarizeAllItemResult> }> = [];

  const enqueueNext = () => {
    if (cursor >= queue.length) {
      return;
    }
    const job = queue[cursor++];
    const promise = runJob(job.index, parsed.data.datasetId, job.host, options.signal);
    inFlight.push({ index: job.index, promise });
  };

  for (let i = 0; i < concurrency; i += 1) {
    enqueueNext();
  }

  while (inFlight.length > 0) {
    const wrapped = inFlight.map(({ promise, index }) =>
      promise.then((value) => ({ value, index })),
    );
    const { value, index } = await Promise.race(wrapped);
    const removeIndex = inFlight.findIndex((entry) => entry.index === index);
    if (removeIndex !== -1) {
      inFlight.splice(removeIndex, 1);
    }
    yield value;
    enqueueNext();
  }
}

async function runJob(
  index: number,
  datasetId: string,
  host: NormalizedHost,
  signal?: AbortSignal,
): Promise<SummarizeAllItemResult> {
  if (signal?.aborted) {
    signal.throwIfAborted();
  }
  const result = await summarizeHost({ datasetId, ip: host.ip });
  return { index, host, result };
}
