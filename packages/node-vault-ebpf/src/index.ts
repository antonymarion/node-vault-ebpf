import { VaultClient } from "./client";
import type { ClientOptions } from "./types";

function nodeVaultEbpf(options?: ClientOptions): VaultClient {
  return new VaultClient(options);
}

export = nodeVaultEbpf;
