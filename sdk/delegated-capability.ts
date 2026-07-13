import type { StableUnitCode } from "./stable-units.js";

export type CapabilityOperation =
  | "consume_pru"
  | "consolidate_pru"
  | "authorize_settlement"
  | "lock_fragmented_pru"
  | "release_fragmented_pru";

export interface DelegatedCapabilityGrant {
  purpose: string;
  allowedOperations: CapabilityOperation[];
  maxAmountPerEpoch: {
    unit: "stable_units";
    stableUnit: StableUnitCode;
    amount: number;
  };
  expiryEpoch: number;
  nonce: string;
}

export interface CapabilityUsage {
  purpose: string;
  operation: CapabilityOperation;
  stableUnit: StableUnitCode;
  amount: number;
  currentEpoch: number;
  amountUsedThisEpoch: number;
  nonce: string;
}

export function validateCapabilityUsage(
  grant: DelegatedCapabilityGrant,
  usage: CapabilityUsage,
  consumedNonces: ReadonlySet<string> = new Set()
): { ok: boolean; reason?: string } {
  if (consumedNonces.has(usage.nonce)) return { ok: false, reason: "nonce already consumed" };
  if (usage.purpose !== grant.purpose) return { ok: false, reason: "purpose mismatch" };
  if (!grant.allowedOperations.includes(usage.operation)) return { ok: false, reason: "operation not allowed" };
  if (usage.currentEpoch > grant.expiryEpoch) return { ok: false, reason: "capability expired" };
  if (usage.stableUnit !== grant.maxAmountPerEpoch.stableUnit) return { ok: false, reason: "stable unit mismatch" };
  if (usage.amount <= 0) return { ok: false, reason: "amount must be positive" };
  if (usage.amountUsedThisEpoch + usage.amount > grant.maxAmountPerEpoch.amount) {
    return { ok: false, reason: "epoch limit exceeded" };
  }
  return { ok: true };
}
