export const DEFAULT_PURPOSE_IDS = [
  "default",
  "tin-receiving",
  "payment",
  "trading",
  "subscription",
  "governance",
  "social",
  "nft",
  "custom",
] as const;

export const PROTOCOL_NATIVE_PURPOSE_IDS = [
  "trustlink-tsn",
  "tsn-settlement",
  "tsn-consolidation",
  "tsn-liquidity",
] as const;

export type DefaultPurposeId = (typeof DEFAULT_PURPOSE_IDS)[number];
export type ProtocolNativePurposeId = (typeof PROTOCOL_NATIVE_PURPOSE_IDS)[number];
export type StandardPurposeId = DefaultPurposeId | ProtocolNativePurposeId;

const STANDARD_PURPOSE_IDS = new Set<string>([
  ...DEFAULT_PURPOSE_IDS,
  ...PROTOCOL_NATIVE_PURPOSE_IDS,
]);

export function isStandardPurposeId(purposeId: string): purposeId is StandardPurposeId {
  return STANDARD_PURPOSE_IDS.has(purposeId);
}

export function assertPurposeId(purposeId: string): void {
  if (!purposeId || purposeId.trim() !== purposeId) {
    throw new Error("Purpose ID must be a non-empty canonical string.");
  }
}

export function assertStandardPurposeId(purposeId: string): asserts purposeId is StandardPurposeId {
  assertPurposeId(purposeId);
  if (!isStandardPurposeId(purposeId)) {
    throw new Error(`Unsupported standard purpose ID: ${purposeId}`);
  }
}
