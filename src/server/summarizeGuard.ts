import "server-only";

export const SUMMARIZE_RATE_LIMIT = 6;
export const SUMMARIZE_WINDOW_MS = 60_000;
export const SUMMARIZE_MAX_CONCURRENCY = 2;

const hitsBySession = new Map<string, number[]>();
let activeSummaries = 0;

export function consumeSummarizeRateLimit(sessionId: string, now = Date.now()): boolean {
  const windowStart = now - SUMMARIZE_WINDOW_MS;
  const recent = (hitsBySession.get(sessionId) ?? []).filter(
    (stamp) => stamp > windowStart,
  );
  if (recent.length >= SUMMARIZE_RATE_LIMIT) {
    hitsBySession.set(sessionId, recent);
    return false;
  }

  recent.push(now);
  hitsBySession.set(sessionId, recent);
  return true;
}

export function tryAcquireSummarizeSlot(): boolean {
  if (activeSummaries >= SUMMARIZE_MAX_CONCURRENCY) {
    return false;
  }

  activeSummaries += 1;
  return true;
}

export function releaseSummarizeSlot(): void {
  activeSummaries = Math.max(0, activeSummaries - 1);
}

export function resetSummarizeGuards(): void {
  hitsBySession.clear();
  activeSummaries = 0;
}
