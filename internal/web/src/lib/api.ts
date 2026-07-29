import type {
  SessionInfo,
  SessionLoginInfo,
  SessionLoginRequest,
  SessionVerifyInfo,
  SessionVerifyRequest,
} from './types.js';

const BASE = '/api';

//
// Response envelope — mirrors Go's rest/models.go:
//   StatusResponse              { success, status, code? }
//   ExtendedStatusResponse[T]   { success, status, code?, data: T }
//

interface StatusResponse {
  success: boolean;
  status: number;
  code?: string;
}

interface ExtendedStatusResponse<T> extends StatusResponse {
  data: T;
}

/**
 * Unwrap the idpd REST envelope.
 *
 * Every endpoint returns { success, status, ... }.
 * Success (2xx) with `data` → return data.
 * Success (2xx) without `data` → return the envelope itself (StatusResponse).
 * Failure → throw.
 */
async function unwrap<T>(res: Response): Promise<T> {
  const envelope: ExtendedStatusResponse<T> | StatusResponse = await res.json();

  if (!envelope.success) {
    throw new Error(`API error ${envelope.status}${envelope.code ? ` (${envelope.code})` : ''}`);
  }

  if ('data' in envelope && envelope.data !== undefined) {
    return envelope.data as T;
  }

  return envelope as unknown as T;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return unwrap<T>(res);
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return unwrap<T>(res);
}

//
// API surface — each method returns unwrapped data.
// GET /api/session/login/{id} → ExtendedStatusResponse<SessionLoginInfo> → SessionLoginInfo
// POST /api/session/login/{id} → StatusResponse → { success, status }
//

export interface LoginOk {
  success: boolean;
  status: number;
}

export interface VerifyOk {
  success: boolean;
  status: number;
  redirect?: string;
}

export const api = {
  /** GET /api/session — returns session info if authenticated */
  session: () => get<SessionInfo>('/session'),

  /** GET /api/session/login/{id} — returns login-hint + allowed verifications */
  sessionLoginInfo: (id: string) =>
    get<SessionLoginInfo>(`/session/login/${id}`),

  /** POST /api/session/login/{id} — submit credentials */
  sessionLogin: (id: string, req: SessionLoginRequest) =>
    post<LoginOk>(`/session/login/${id}`, req),

  /** GET /api/session/verify/{id} — returns verification method */
  sessionVerifyInfo: (id: string) =>
    get<SessionVerifyInfo>(`/session/verify/${id}`),

  /** POST /api/session/verify/{id} — submit verification response */
  sessionVerify: (id: string, req: SessionVerifyRequest) =>
    post<LoginOk>(`/session/verify/${id}`, req),
};
