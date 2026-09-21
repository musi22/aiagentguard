export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/$/, '');
export class ApiError extends Error { constructor(message: string, public status: number, public details?: unknown) { super(message); } }
export type Me = { user: { id:string; email:string; name:string }; organization:{id:string;name:string;plan:string}; role:string; csrf_token?:string; workspaces:Array<{id:string;name:string;environment?:string}>; teams:Array<{id:string;name:string;workspace_id?:string}> };

export function rememberSession(value: Me) {
  if (typeof sessionStorage !== 'undefined' && value.csrf_token) sessionStorage.setItem('agentguard_csrf', value.csrf_token);
}
export function csrfToken() {
  if (typeof document === 'undefined') return '';
  const match = document.cookie.match(/(?:^|; )ag_csrf_bootstrap=([^;]+)/);
  if (match) {
    const token = decodeURIComponent(match[1]);
    sessionStorage.setItem('agentguard_csrf', token);
    document.cookie = 'ag_csrf_bootstrap=; Max-Age=0; path=/; SameSite=Lax';
  }
  return sessionStorage.getItem('agentguard_csrf') || '';
}
let refreshing: Promise<Me> | undefined;
export async function refreshSession(): Promise<Me> {
  if (!refreshing) {
    refreshing = request<Me>('/auth/refresh', { method:'POST', body:'{}' }, undefined, false)
      .then(value=>{rememberSession(value);return value})
      .finally(()=>{refreshing=undefined});
  }
  return refreshing;
}
async function request<T>(path: string, options: RequestInit = {}, csrf?: string, allowRefresh=true): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  const token = csrf || csrfToken();
  if (token && !['GET', 'HEAD'].includes(options.method || 'GET')) headers.set('X-CSRF-Token', token);
  const response = await fetch(`${API_BASE}/api/v1${path}`, { ...options, headers, credentials: 'include' });
  if (response.status===401 && allowRefresh && !['/auth/login','/auth/register','/auth/refresh','/auth/magic-link/consume'].includes(path)) {
    await refreshSession();
    return request<T>(path, options, csrfToken(), false);
  }
  if (!response.ok) {
    const raw = await response.text();
    let detail:unknown=raw;
    try { detail=JSON.parse(raw) } catch { /* Non-JSON upstream errors remain readable. */ }
    const message = typeof detail==='object' && detail && 'detail' in detail
      ? (typeof (detail as {detail:unknown}).detail==='string' ? String((detail as {detail:unknown}).detail) : JSON.stringify((detail as {detail:unknown}).detail))
      : `Request failed (${response.status})`;
    throw new ApiError(message, response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown, csrf?: string) => request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) }, csrf),
  patch: <T>(path: string, body: unknown, csrf?: string) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }, csrf),
  delete: <T>(path: string, csrf?: string) => request<T>(path, { method: 'DELETE' }, csrf),
};
export async function currentSession():Promise<Me> {
  const me = await api.get<Me>('/auth/me');
  if (!csrfToken()) return refreshSession();
  return {...me,csrf_token:csrfToken()};
}
export function asList<T>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === 'object') {
    const obj=value as Record<string,unknown>;
    for (const key of ['items','results','data','agents','tools','policies','budgets','approvals','requests','events','members','teams','workspaces','integrations','credentials'])
      if (Array.isArray(obj[key])) return obj[key] as T[];
  }
  return [];
}
