export type Decision = "allow" | "deny" | "require_approval" | "rate_limited" | "budget_exceeded" | "agent_disabled";
export interface AuthorizeRequest { agent_id?: string; tool: string; arguments: Record<string, unknown>; context: Record<string, unknown>; idempotency_key?: string }
export interface AuthorizeResponse { decision: Decision; request_id: string; approval_id?: string; risk_score?: number; reason: string; status?: string; result?: unknown }
export interface AgentGuardOptions { apiKey: string; baseUrl?: string; agentId?: string; timeoutMs?: number; approvalTimeoutMs?: number; pollIntervalMs?: number; fetch?: typeof fetch }
export interface ExecutionClaim { claim_token: string; arguments: Record<string, unknown>; context: Record<string, unknown> }
export interface ProtectOptions<A extends unknown[]> {
  context?: Record<string, unknown> | ((...args: A) => Record<string, unknown>);
  mapArguments?: (...args: A) => Record<string, unknown>;
  applyArguments?: (frozen: Record<string, unknown>, original: A) => A;
}

export class AgentGuardError extends Error {}
export class AuthorizationDenied extends AgentGuardError { constructor(message: string, public readonly requestId?: string) { super(message); } }
export class ApprovalTimeout extends AgentGuardError {}
export class ServiceUnavailable extends AgentGuardError {}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class AgentGuard {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly approvalTimeoutMs: number;
  private readonly pollIntervalMs: number;
  private readonly doFetch: typeof fetch;
  constructor(private readonly options: AgentGuardOptions) {
    if (!options.apiKey) throw new TypeError("apiKey is required");
    this.baseUrl = (options.baseUrl ?? "http://localhost:8000").replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.approvalTimeoutMs = options.approvalTimeoutMs ?? 300_000;
    this.pollIntervalMs = options.pollIntervalMs ?? 1_000;
    this.doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }
  private payload(tool: string, args: Record<string, unknown>, context: Record<string, unknown>, idempotencyKey?: string): AuthorizeRequest {
    return {tool, arguments: args, context, ...(this.options.agentId ? {agent_id: this.options.agentId} : {}), ...(idempotencyKey ? {idempotency_key: idempotencyKey} : {})};
  }
  private async request<T = AuthorizeResponse>(path: string, init: RequestInit, retry = false): Promise<T> {
    const attempts = retry ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt++) {
      const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await this.doFetch(this.baseUrl + path, {...init, signal: controller.signal, headers: {"Authorization": `Bearer ${this.options.apiKey}`, "Content-Type": "application/json", "User-Agent": "agentguard-typescript/0.1.0", ...init.headers}});
        if (!response.ok) throw new ServiceUnavailable(`AgentGuard returned HTTP ${response.status}; action was not executed`);
        const data: unknown = await response.json();
        if (!data || typeof data !== "object") throw new ServiceUnavailable("AgentGuard returned an invalid response; action was not executed");
        return data as T;
      } catch (error) {
        if (error instanceof ServiceUnavailable) throw error;
        if (attempt + 1 === attempts) throw new ServiceUnavailable("AgentGuard is unavailable; action was not executed", {cause: error});
      } finally { clearTimeout(timeout); }
    }
    throw new ServiceUnavailable("AgentGuard is unavailable; action was not executed");
  }
  authorize(tool: string, args: Record<string, unknown> = {}, options: {context?: Record<string, unknown>; idempotencyKey?: string} = {}) {
    return this.request("/api/v1/authorize", {method: "POST", body: JSON.stringify(this.payload(tool, args, options.context ?? {}, options.idempotencyKey))}, Boolean(options.idempotencyKey));
  }
  // Gateway execution can have side effects and therefore never retries.
  async execute(tool: string, args: Record<string, unknown> = {}, options: {context?: Record<string, unknown>; idempotencyKey?: string} = {}) {
    const initial = await this.request("/api/v1/execute", {method: "POST", body: JSON.stringify(this.payload(tool, args, options.context ?? {}, options.idempotencyKey))});
    if (initial.decision !== "require_approval") return initial;
    const state = await this.waitForApproval(initial); const id = initial.request_id || state.request_id;
    return this.request(`/api/v1/requests/${encodeURIComponent(id)}/execute`, {method: "POST", body: "{}"});
  }
  private async waitForApproval(initial: AuthorizeResponse): Promise<AuthorizeResponse> {
    if (initial.decision !== "allow" && initial.decision !== "require_approval") throw new AuthorizationDenied(initial.reason || "Action denied", initial.request_id);
    if (!initial.request_id) throw new ServiceUnavailable("AgentGuard omitted request_id; action was not executed");
    if (initial.decision === "allow") return initial;
    const deadline = Date.now() + this.approvalTimeoutMs;
    while (Date.now() < deadline) {
      const state = await this.request(`/api/v1/requests/${encodeURIComponent(initial.request_id)}`, {method: "GET"});
      if (state.status === "approved" || state.status === "allowed") return state;
      if (["rejected", "denied", "expired", "cancelled", "failed"].includes(state.status ?? "")) throw new AuthorizationDenied(state.reason || `Approval ${state.status}`, initial.request_id);
      await sleep(this.pollIntervalMs);
    }
    throw new ApprovalTimeout(`Approval timed out for request ${initial.request_id}`);
  }
  /** Protect a local function; it executes once and only after the request is claimed. */
  protect<A extends unknown[], R>(tool: string, fn: (...args: A) => R | Promise<R>, options: ProtectOptions<A> = {}): (...args: A) => Promise<Awaited<R>> {
    if (!tool) throw new TypeError("tool is required");
    return async (...args: A): Promise<Awaited<R>> => {
      const callArgs = options.mapArguments ? options.mapArguments(...args) : {args};
      const context = typeof options.context === "function" ? options.context(...args) : (options.context ?? {});
      const initial = await this.authorize(tool, callArgs, {context, idempotencyKey: crypto.randomUUID()});
      const state = await this.waitForApproval(initial); const id = initial.request_id || state.request_id;
      const claim = await this.request<ExecutionClaim>(`/api/v1/requests/${encodeURIComponent(id)}/claim`, {method: "POST", body: "{}"});
      if (!claim || typeof claim.claim_token !== "string" || !claim.claim_token || !claim.arguments || typeof claim.arguments !== "object" || !claim.context || typeof claim.context !== "object") throw new ServiceUnavailable("AgentGuard returned an invalid execution claim; action was not executed");
      let executionArgs: A;
      if (options.applyArguments) executionArgs = options.applyArguments(claim.arguments, args);
      else if (!options.mapArguments && Array.isArray(claim.arguments.args)) executionArgs = claim.arguments.args as unknown as A;
      else throw new ServiceUnavailable("A custom argument mapper requires applyArguments for frozen execution; action was not executed");
      try {
        const result = await fn(...executionArgs);
        await this.request(`/api/v1/requests/${encodeURIComponent(id)}/result`, {method: "POST", headers: {"X-AgentGuard-Claim": claim.claim_token}, body: JSON.stringify({status: "succeeded", result})});
        return result as Awaited<R>;
      } catch (error) {
        try { await this.request(`/api/v1/requests/${encodeURIComponent(id)}/result`, {method: "POST", headers: {"X-AgentGuard-Claim": claim.claim_token}, body: JSON.stringify({status: "failed", result: {error_type: error instanceof Error ? error.name : "UnknownError"}})}); }
        catch { /* preserve the actual tool failure */ }
        throw error;
      }
    };
  }
}
