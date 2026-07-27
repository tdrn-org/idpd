import type { SessionInfo, SessionLoginInfo, SessionLoginRequest, SessionVerifyInfo, SessionVerifyRequest } from './types.js';

const BASE = '/api';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

async function postNoBody(path: string): Promise<Response> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return res;
}

export const api = {
  session: () => get<SessionInfo>('/session'),

  sessionLoginInfo: (id: string) =>
    get<SessionLoginInfo>(`/session/login/${id}`),

  sessionLogin: (req: SessionLoginRequest) =>
    post<{ ok: boolean }>('/session/login', req),

  sessionVerifyInfo: (id: string) =>
    get<SessionVerifyInfo>(`/session/verify/${id}`),

  sessionVerify: (req: SessionVerifyRequest) =>
    post<{ ok: boolean; redirect?: string }>('/session/verify', req),

  startSession: () =>
    postNoBody('/session'),
};
