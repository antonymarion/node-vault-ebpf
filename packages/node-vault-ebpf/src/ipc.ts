import * as net from "node:net";
import { randomUUID } from "node:crypto";
import type { AgentEnvelope, AgentResult } from "./types";

const DEFAULT_TIMEOUT_MS = 30_000;

export type AgentAddress =
  | { kind: "unix"; path: string }
  | { kind: "tcp"; host: string; port: number };

export function parseAgentAddress(socket: string): AgentAddress {
  if (socket.startsWith("tcp://")) {
    const u = new URL(socket);
    const port = Number(u.port);
    if (!u.hostname || !port) {
      throw new Error(`invalid tcp agent address: ${socket}`);
    }
    return { kind: "tcp", host: u.hostname, port };
  }
  // host:port convenience for tests
  const m = /^([^:/]+):(\d+)$/.exec(socket);
  if (m) {
    return { kind: "tcp", host: m[1], port: Number(m[2]) };
  }
  return { kind: "unix", path: socket };
}

export class AgentClient {
  private readonly address: AgentAddress;

  constructor(
    socketPath: string,
    private readonly timeoutMs = DEFAULT_TIMEOUT_MS,
  ) {
    this.address = parseAgentAddress(socketPath);
  }

  async call(
    method: string,
    params: Record<string, unknown> = {},
  ): Promise<unknown> {
    const id = randomUUID();
    const envelope: AgentEnvelope = { id, method, params };
    const payload = `${JSON.stringify(envelope)}\n`;

    return new Promise((resolve, reject) => {
      const socket =
        this.address.kind === "tcp"
          ? net.createConnection(this.address.port, this.address.host)
          : net.createConnection(this.address.path);

      let buffer = "";
      let settled = false;

      const finish = (err?: Error, value?: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (err) reject(err);
        else resolve(value);
      };

      const timer = setTimeout(() => {
        finish(new Error(`agent IPC timeout after ${this.timeoutMs}ms`));
      }, this.timeoutMs);

      socket.on("connect", () => {
        socket.write(payload);
      });

      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const nl = buffer.indexOf("\n");
        if (nl === -1) return;
        const line = buffer.slice(0, nl);
        try {
          const msg = JSON.parse(line) as AgentResult;
          if (msg.id !== id) {
            finish(new Error("agent IPC response id mismatch"));
            return;
          }
          if (!msg.ok) {
            const err = new Error(msg.error?.message ?? "agent error") as Error & {
              response?: { statusCode: number; body: unknown };
            };
            if (msg.error?.statusCode != null) {
              err.response = {
                statusCode: msg.error.statusCode,
                body: msg.error.body,
              };
            }
            finish(err);
            return;
          }
          finish(undefined, msg.result);
        } catch (e) {
          finish(e instanceof Error ? e : new Error(String(e)));
        }
      });

      socket.on("error", (err) => {
        const where =
          this.address.kind === "tcp"
            ? `tcp://${this.address.host}:${this.address.port}`
            : this.address.path;
        finish(
          new Error(
            `cannot connect to node-vault-ebpf agent at ${where}: ${err.message}`,
          ),
        );
      });
    });
  }
}
