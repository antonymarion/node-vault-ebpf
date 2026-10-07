export interface ClientOptions {
  apiVersion?: string;
  endpoint?: string;
  token?: string;
  namespace?: string;
  pathPrefix?: string;
  noCustomHTTPVerbs?: boolean;
  requestOptions?: Record<string, unknown>;
  /** Unix socket path for the privileged agent (default: /var/run/node-vault-ebpf.sock). */
  agentSocket?: string;
  /** Default allowed TLS destinations for scrubbed secrets. */
  allowedHosts?: string[];
  /**
   * When true, skip eBPF map registration (agent still proxies Vault).
   * Intended for unit tests only — never enable in production.
   */
  passthrough?: boolean;
}

export interface RequestOptions {
  path?: string;
  method?: string;
  json?: unknown;
  headers?: Record<string, string>;
  qs?: Record<string, string | number | boolean | undefined>;
  allowedHosts?: string[];
  [key: string]: unknown;
}

export interface VaultError extends Error {
  response?: {
    statusCode: number;
    body: unknown;
  };
}

export interface AgentEnvelope {
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

export interface AgentResult {
  id: string;
  ok: boolean;
  result?: unknown;
  error?: {
    message: string;
    statusCode?: number;
    body?: unknown;
  };
}
