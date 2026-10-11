import "server-only";

import { randomUUID } from "node:crypto";

import { cookies } from "next/headers";

export const SESSION_COOKIE_NAME = "dsa_session";

const SESSION_TTL_MS = 15 * 60 * 1000;
const SESSION_MAX_AGE_SECONDS = SESSION_TTL_MS / 1000;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface SessionRecord {
  id: string;
  createdAt: number;
}

const sessions = new Map<string, SessionRecord>();

function pruneSessions(now: number): void {
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      sessions.delete(id);
    }
  }
}

function isSessionId(value: string | undefined): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

export async function readSession(): Promise<SessionRecord | null> {
  const now = Date.now();
  pruneSessions(now);
  const jar = await cookies();
  const candidate = jar.get(SESSION_COOKIE_NAME)?.value;
  if (!isSessionId(candidate)) {
    return null;
  }

  const record = sessions.get(candidate);
  if (!record || now - record.createdAt > SESSION_TTL_MS) {
    return null;
  }

  return record;
}

export async function getOrCreateSession(): Promise<SessionRecord> {
  const existing = await readSession();
  if (existing) {
    return existing;
  }

  const record: SessionRecord = {
    id: randomUUID(),
    createdAt: Date.now(),
  };
  sessions.set(record.id, record);

  const jar = await cookies();
  jar.set(SESSION_COOKIE_NAME, record.id, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
  });

  return record;
}

export function clearSessions(): void {
  sessions.clear();
}
