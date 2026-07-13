export type StableUnitCode = "USD" | "NGN" | "INR" | "AED" | "EUR" | (string & {});

export interface StableAssetPolicy {
  assetId: string;
  stableUnit: StableUnitCode;
  decimals: number;
  stableUnitPower: number;
  enabled: boolean;
}

export interface StableAssetValuation {
  assetId: string;
  assetAmount: number;
  stableUnit: StableUnitCode;
  stableUnitPower: number;
  stableAmount: number;
}

export function valueStableAsset(policy: StableAssetPolicy, assetBaseUnits: bigint): StableAssetValuation {
  if (!policy.enabled) throw new Error(`Stable asset is not enabled: ${policy.assetId}`);
  if (assetBaseUnits < 0n) throw new Error("Asset amount cannot be negative.");
  if (!Number.isInteger(policy.decimals) || policy.decimals < 0) throw new Error("Asset decimals are invalid.");
  if (!Number.isFinite(policy.stableUnitPower) || policy.stableUnitPower <= 0) {
    throw new Error("Stable Unit Power must be positive.");
  }

  const assetAmount = Number(assetBaseUnits) / 10 ** policy.decimals;
  return {
    assetId: policy.assetId,
    assetAmount,
    stableUnit: policy.stableUnit,
    stableUnitPower: policy.stableUnitPower,
    stableAmount: assetAmount * policy.stableUnitPower,
  };
}
