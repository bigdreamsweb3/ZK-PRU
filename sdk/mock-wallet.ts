/**
 * Deterministic mock wallet — for tests and local development only.
 * Signs fixed messages/typed data deterministically so identity
 * derivation is reproducible across calls, matching what a real wallet
 * would do for the two fixed EIP-712 challenges in
 * docs/03-identity-model.md.
 */
import { hash2, stringToField } from "./poseidon.js";
import type { EIP712Domain, WalletSigner } from "./types.js";

export class MockWallet implements WalletSigner {
  constructor(public readonly address: string, private readonly secretKey: string) {}

  async signMessage(message: string): Promise<string> {
    // NOT a real signature scheme — deterministic stand-in only.
    // A production integration must use the real wallet's signing API.
    return hash2(stringToField(this.secretKey), stringToField(message)).toString();
  }

  async signTypedData(
    domain: EIP712Domain,
    types: Record<string, Array<{ name: string; type: string }>>,
    message: Record<string, unknown>
  ): Promise<string> {
    // NOT real EIP-712 signing — deterministic stand-in only. A real
    // wallet integration must use eth_signTypedData_v4 (or equivalent),
    // which is what actually gives the phishing-resistance property
    // described in docs/03-identity-model.md — the domain fields must
    // be rendered by the real wallet UI, not simulated here.
    const payload = JSON.stringify({ domain, types, message });
    return hash2(stringToField(this.secretKey), stringToField(payload)).toString();
  }
}
