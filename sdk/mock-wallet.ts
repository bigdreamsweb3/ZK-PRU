/**
 * Deterministic mock Solana wallet for tests and local development only.
 */
import { hash2, stringToField } from "./poseidon.js";
import type { WalletSigner } from "./types.js";

export class MockWallet implements WalletSigner {
  constructor(public readonly publicKey: string, private readonly secretKey: string) {}

  async signMessage(message: Uint8Array): Promise<string> {
    const decodedMessage = new TextDecoder().decode(message);
    return hash2(stringToField(this.secretKey), stringToField(decodedMessage)).toString();
  }
}
