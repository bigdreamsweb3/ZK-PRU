import { describe, expect, it } from "vitest";
import { isStandardPurposeId } from "../sdk/purpose.js";
import { valueStableAsset } from "../sdk/stable-units.js";
import { validateCapabilityUsage, type DelegatedCapabilityGrant } from "../sdk/delegated-capability.js";

describe("final architecture primitives", () => {
  it("recognizes standardized purpose IDs", () => {
    expect(isStandardPurposeId("tin-receiving")).toBe(true);
    expect(isStandardPurposeId("tsn-settlement")).toBe(true);
    expect(isStandardPurposeId("unknown-purpose")).toBe(false);
  });

  it("values stable assets through Stable Unit Power", () => {
    const valuation = valueStableAsset({
      assetId: "USDT",
      stableUnit: "USD",
      decimals: 6,
      stableUnitPower: 0.995,
      enabled: true,
    }, 100_000_000n);

    expect(valuation.assetAmount).toBe(100);
    expect(valuation.stableAmount).toBe(99.5);
  });

  it("rejects delegated capability usage outside scope", () => {
    const grant: DelegatedCapabilityGrant = {
      purpose: "tsn-settlement",
      allowedOperations: ["consume_pru", "authorize_settlement"],
      maxAmountPerEpoch: {
        unit: "stable_units",
        stableUnit: "USD",
        amount: 1000,
      },
      expiryEpoch: 500,
      nonce: "grant-1",
    };

    expect(validateCapabilityUsage(grant, {
      purpose: "tsn-settlement",
      operation: "authorize_settlement",
      stableUnit: "USD",
      amount: 100,
      currentEpoch: 400,
      amountUsedThisEpoch: 200,
      nonce: "use-1",
    }).ok).toBe(true);

    expect(validateCapabilityUsage(grant, {
      purpose: "tsn-settlement",
      operation: "authorize_settlement",
      stableUnit: "USD",
      amount: 900,
      currentEpoch: 400,
      amountUsedThisEpoch: 200,
      nonce: "use-2",
    }).reason).toBe("epoch limit exceeded");

    expect(validateCapabilityUsage(grant, {
      purpose: "tsn-settlement",
      operation: "authorize_settlement",
      stableUnit: "USD",
      amount: 100,
      currentEpoch: 501,
      amountUsedThisEpoch: 0,
      nonce: "use-3",
    }).reason).toBe("capability expired");
  });
});
