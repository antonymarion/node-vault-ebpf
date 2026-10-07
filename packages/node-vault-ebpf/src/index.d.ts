import type { ClientOptions, RequestOptions, VaultError } from "./types";
import { VaultClient } from "./client";

declare function nodeVaultEbpf(options?: ClientOptions): VaultClient;

declare namespace nodeVaultEbpf {
  export type { ClientOptions, RequestOptions, VaultError };
  export { VaultClient };
}

export = nodeVaultEbpf;
