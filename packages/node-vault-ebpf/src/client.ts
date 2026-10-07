import { EventEmitter } from "node:events";
import { AgentClient } from "./ipc";
import type { ClientOptions, RequestOptions, VaultError } from "./types";

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

function vaultError(message: string, statusCode?: number, body?: unknown): VaultError {
  const err = new Error(message) as VaultError;
  if (statusCode != null) {
    err.response = { statusCode, body };
  }
  return err;
}

export class VaultClient extends EventEmitter {
  apiVersion: string;
  endpoint: string;
  token: string;
  namespace: string;
  pathPrefix: string;
  noCustomHTTPVerbs: boolean;
  requestOptions: Record<string, unknown>;
  agentSocket: string;
  allowedHosts: string[];
  passthrough: boolean;
  kubernetesPath = "kubernetes";

  private agent: AgentClient;
  private bootstrapped = false;

  constructor(options: ClientOptions = {}) {
    super();
    this.apiVersion = options.apiVersion ?? "v1";
    this.endpoint = stripTrailingSlash(
      options.endpoint ?? process.env.VAULT_ADDR ?? "http://127.0.0.1:8200",
    );
    this.token = options.token ?? process.env.VAULT_TOKEN ?? "";
    this.namespace = options.namespace ?? process.env.VAULT_NAMESPACE ?? "";
    this.pathPrefix = options.pathPrefix ?? process.env.VAULT_PREFIX ?? "";
    this.noCustomHTTPVerbs = options.noCustomHTTPVerbs ?? false;
    this.requestOptions = options.requestOptions ?? {};
    this.agentSocket =
      options.agentSocket ??
      process.env.NVE_AGENT_SOCKET ??
      "/var/run/node-vault-ebpf.sock";
    this.allowedHosts = options.allowedHosts ?? [];
    this.passthrough = options.passthrough ?? false;
    this.agent = new AgentClient(this.agentSocket);
  }

  private async ensureBootstrap(): Promise<void> {
    if (this.bootstrapped) return;
    await this.agent.call("bootstrap", {
      endpoint: this.endpoint,
      token: this.token,
      namespace: this.namespace,
      pathPrefix: this.pathPrefix,
      apiVersion: this.apiVersion,
      noCustomHTTPVerbs: this.noCustomHTTPVerbs,
      passthrough: this.passthrough,
      allowedHosts: this.allowedHosts,
      pid: process.pid,
    });
    // Clear token from the Node process after handoff (weaker mode mitigation).
    if (this.token) {
      this.token = "";
      if (process.env.VAULT_TOKEN) {
        delete process.env.VAULT_TOKEN;
      }
    }
    this.bootstrapped = true;
  }

  async request(options: RequestOptions = {}): Promise<unknown> {
    await this.ensureBootstrap();
    const method = (options.method ?? "GET").toUpperCase();
    const path = options.path ?? "";
    try {
      return await this.agent.call("vault.request", {
        method,
        path,
        json: options.json,
        headers: options.headers,
        qs: options.qs,
        allowedHosts: options.allowedHosts ?? this.allowedHosts,
        scrub: method === "GET" || path.includes("?"),
      });
    } catch (e) {
      const err = e as VaultError;
      if (err.response) throw err;
      throw vaultError(err.message);
    }
  }

  async read(path: string, requestOptions: RequestOptions = {}): Promise<unknown> {
    return this.request({
      ...requestOptions,
      method: "GET",
      path,
      scrub: true,
    } as RequestOptions);
  }

  async write(
    path: string,
    data: unknown,
    requestOptions: RequestOptions = {},
  ): Promise<unknown> {
    return this.request({
      ...requestOptions,
      method: "POST",
      path,
      json: data,
    });
  }

  async update(
    path: string,
    data: unknown,
    requestOptions: RequestOptions = {},
  ): Promise<unknown> {
    return this.request({
      ...requestOptions,
      method: "PATCH",
      path,
      json: data,
      headers: {
        ...(requestOptions.headers ?? {}),
        "Content-Type": "application/merge-patch+json",
      },
    });
  }

  async delete(path: string, requestOptions: RequestOptions = {}): Promise<unknown> {
    return this.request({
      ...requestOptions,
      method: "DELETE",
      path,
    });
  }

  async list(path: string, requestOptions: RequestOptions = {}): Promise<unknown> {
    if (this.noCustomHTTPVerbs) {
      return this.request({
        ...requestOptions,
        method: "GET",
        path,
        qs: { ...(requestOptions.qs as object), list: "1" },
      });
    }
    return this.request({
      ...requestOptions,
      method: "LIST",
      path,
    });
  }

  async help(path: string, requestOptions: RequestOptions = {}): Promise<unknown> {
    return this.request({
      ...requestOptions,
      method: "GET",
      path,
      qs: { help: "1" },
    });
  }

  async approleLogin(opts: {
    role_id: string;
    secret_id?: string;
    mount_point?: string;
  }): Promise<unknown> {
    await this.ensureBootstrap();
    const result = (await this.agent.call("vault.approleLogin", opts)) as {
      auth?: { client_token?: string };
    };
    // Token stays in the agent; Node must not retain it.
    this.token = "";
    return result;
  }

  async kubernetesLogin(opts: {
    role: string;
    jwt: string;
    mount_point?: string;
  }): Promise<unknown> {
    await this.ensureBootstrap();
    const result = await this.agent.call("vault.kubernetesLogin", {
      ...opts,
      mount_point: opts.mount_point ?? this.kubernetesPath,
    });
    this.token = "";
    return result;
  }

  async health(): Promise<unknown> {
    return this.agent.call("health", {});
  }
}
