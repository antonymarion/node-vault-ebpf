import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as net from "node:net";
import nodeVaultEbpf from "../src/index";

function startMockAgent(
  handler: (method: string, params: Record<string, unknown>) => unknown,
): Promise<{ address: string; close: () => Promise<void> }> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      let buf = "";
      socket.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        const nl = buf.indexOf("\n");
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        const req = JSON.parse(line) as {
          id: string;
          method: string;
          params?: Record<string, unknown>;
        };
        try {
          const result = handler(req.method, req.params ?? {});
          socket.write(
            `${JSON.stringify({ id: req.id, ok: true, result })}\n`,
          );
        } catch (e) {
          const err = e as Error & { statusCode?: number; body?: unknown };
          socket.write(
            `${JSON.stringify({
              id: req.id,
              ok: false,
              error: {
                message: err.message,
                statusCode: err.statusCode,
                body: err.body,
              },
            })}\n`,
          );
        }
      });
    });

    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("expected TCP address"));
        return;
      }
      resolve({
        address: `tcp://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

describe("node-vault-ebpf client", () => {
  it("factory returns a client with node-vault-like defaults", () => {
    const vault = nodeVaultEbpf({ passthrough: true });
    assert.equal(vault.apiVersion, "v1");
    assert.ok(vault.endpoint.includes("8200"));
    assert.equal(typeof vault.read, "function");
    assert.equal(typeof vault.write, "function");
    assert.equal(typeof vault.list, "function");
  });

  it("read() returns scrubbed vault-shaped body via agent", async () => {
    const mock = await startMockAgent((method, params) => {
      if (method === "bootstrap") return { ok: true };
      if (method === "vault.request") {
        assert.equal(params.method, "GET");
        assert.equal(params.path, "secret/data/demo");
        return {
          request_id: "req-1",
          lease_id: "",
          renewable: false,
          lease_duration: 0,
          data: {
            data: { token: "nve:AAAAAAAAAAAAAAAAAAAA" },
            metadata: { version: 1 },
          },
        };
      }
      throw new Error(`unexpected method ${method}`);
    });

    try {
      const vault = nodeVaultEbpf({
        agentSocket: mock.address,
        token: "s.temporary",
        passthrough: true,
      });
      const body = (await vault.read("secret/data/demo")) as {
        data: { data: { token: string } };
      };
      assert.equal(body.data.data.token, "nve:AAAAAAAAAAAAAAAAAAAA");
      assert.equal(vault.token, "", "token cleared after bootstrap");
    } finally {
      await mock.close();
    }
  });

  it("propagates vault API errors with statusCode", async () => {
    const mock = await startMockAgent((method) => {
      if (method === "bootstrap") return { ok: true };
      const err = new Error("permission denied") as Error & {
        statusCode: number;
        body: { errors: string[] };
      };
      err.statusCode = 403;
      err.body = { errors: ["permission denied"] };
      throw err;
    });

    try {
      const vault = nodeVaultEbpf({
        agentSocket: mock.address,
        passthrough: true,
      });
      await assert.rejects(
        () => vault.read("secret/data/nope"),
        (err: Error & { response?: { statusCode: number } }) => {
          assert.equal(err.message, "permission denied");
          assert.equal(err.response?.statusCode, 403);
          return true;
        },
      );
    } finally {
      await mock.close();
    }
  });

  it("write() proxies POST without scrub flag semantics", async () => {
    const mock = await startMockAgent((method, params) => {
      if (method === "bootstrap") return { ok: true };
      if (method === "vault.request") {
        assert.equal(params.method, "POST");
        assert.deepEqual(params.json, { data: { a: "1" } });
        return { data: { version: 2 } };
      }
      throw new Error(`unexpected ${method}`);
    });

    try {
      const vault = nodeVaultEbpf({ agentSocket: mock.address });
      const res = await vault.write("secret/data/demo", { data: { a: "1" } });
      assert.deepEqual(res, { data: { version: 2 } });
    } finally {
      await mock.close();
    }
  });
});
