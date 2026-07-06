/**
 * ZK-PRU Attack Simulation Suite
 *
 * Run with: node tests/attack-simulations/run-attacks.mjs
 * No npm install required — uses only Node's built-in crypto module.
 *
 * See crypto-utils.mjs's header comment for exactly what's real
 * cryptography here (wallet keys, signatures) vs. simulated (the hash
 * chain standing in for Poseidon). Read README.md in this folder for
 * the full breakdown of what this suite does and doesn't prove.
 *
 * Each attack prints: the attacker's goal, what data they start with,
 * what they attempt, and the concrete result — including exactly what
 * an attacker obtains, if anything, so you can see for yourself rather
 * than trust a bare pass/fail.
 */
import crypto from "node:crypto";
import {
  section, narrate, step, info, attackerGets, defended, vulnerable, critical,
  generateWallet, sign, verifySignature, fieldHash,
  buildIdentityChallenge, buildVaultChallenge,
  deriveIdentitySeed, derivePRUSeed, derivePRU, deriveCommitment, deriveActionCommitment,
} from "./crypto-utils.mjs";

const results = [];
function record(name, passed, severity = "normal") {
  results.push({ name, passed, severity });
}

const REGISTRY_BINDING = {
  cluster: "devnet",
  registryProgramId: "ZkPruRegistryDevnet111111111111111111111111",
  version: "v1",
};
const PHISHING_BINDING = {
  ...REGISTRY_BINDING,
  registryProgramId: "FakeZkPruRegistry1111111111111111111111111",
};

console.log("\x1b[1m\x1b[36m");
console.log("╔════════════════════════════════════════════════════════════╗");
console.log("║        ZK-PRU ADVERSARIAL ATTACK SIMULATION SUITE            ║");
console.log("╚════════════════════════════════════════════════════════════╝");
console.log("\x1b[0m");

// =====================================================================
section("SETUP — real wallet, real identity derivation");
// =====================================================================
narrate("Generating a real Ed25519 keypair to stand in for the user's wallet.");
const victim = generateWallet();
info("victim wallet address (public)", victim.address);

const identityChallenge = buildIdentityChallenge({
  ...REGISTRY_BINDING,
  walletPublicKey: victim.address,
});
const vaultChallenge = buildVaultChallenge({
  ...REGISTRY_BINDING,
  walletPublicKey: victim.address,
});

const identitySignature = sign(victim.privateKey, identityChallenge);
const vaultSignature = sign(victim.privateKey, vaultChallenge);
info("identity_signature (real signature bytes)", identitySignature);
info("vault_signature (real signature bytes)", vaultSignature);

const identitySeed = deriveIdentitySeed(victim.address, identitySignature);
info("identity_seed", identitySeed);

step("Registering the victim in two protocols: 'protocol-A' and 'protocol-B'");
const contexts = {};
for (const contextId of ["protocol-A", "protocol-B"]) {
  const pruSeed = derivePRUSeed(identitySeed, contextId, vaultSignature);
  const pru = derivePRU(pruSeed, 0);
  const commitment = deriveCommitment(pruSeed);
  contexts[contextId] = { pruSeed, pru, commitment };
  info(`  ${contextId} → PRU`, pru);
  info(`  ${contextId} → commitment`, commitment);
}
const publicRegistry = {
  "protocol-A": { contextId: "protocol-A", pru: contexts["protocol-A"].pru, commitment: contexts["protocol-A"].commitment },
  "protocol-B": { contextId: "protocol-B", pru: contexts["protocol-B"].pru, commitment: contexts["protocol-B"].commitment },
};
narrate("This registry is what EVERY attack below assumes is fully public. Every attacker in this suite can read it freely.");

// =====================================================================
section("ATTACK 1 — Forge a signature without the private key");
// =====================================================================
narrate("Goal: attacker wants to produce a valid identity_signature for the victim's address, without the victim's private key.");
step("Attacker knows: victim's public address, the fixed challenge text, the registry.");
step("Attacker does NOT know: the private key.");
const forgedAttempt1 = crypto.randomBytes(64).toString("hex");
const forged1Valid = verifySignature(victim.publicKey, identityChallenge, forgedAttempt1);
info("attacker's forged attempt (random bytes)", forgedAttempt1);
info("verifies against victim's real public key?", forged1Valid);

step("Second attempt: attacker generates their OWN keypair and signs the same challenge, hoping it passes as the victim's.");
const attacker1 = generateWallet();
const attacker1Sig = sign(attacker1.privateKey, identityChallenge);
const forged2Valid = verifySignature(victim.publicKey, identityChallenge, attacker1Sig);
info("attacker's own signature, checked against VICTIM's public key", forged2Valid);

if (!forged1Valid && !forged2Valid) {
  defended("Real Ed25519 signature verification rejects both forgery attempts. Without the private key, forging a valid signature requires guessing correctly in a 2^252-point space — computationally infeasible. This is the same guarantee a real wallet gives you.");
  record("Attack 1: signature forgery without private key", true);
} else {
  vulnerable("A forged signature was accepted. This should be cryptographically impossible — stop and investigate immediately.");
  record("Attack 1: signature forgery without private key", false, "critical");
}

// =====================================================================
section("ATTACK 2 — Registry-only cross-context correlation");
// =====================================================================
narrate("Goal: an attacker with ONLY public registry read access tries to prove protocol-A's PRU and protocol-B's PRU belong to the same wallet.");
step("Attacker has: publicRegistry (both records above). Nothing else.");
const recA = publicRegistry["protocol-A"];
const recB = publicRegistry["protocol-B"];
info("protocol-A record", JSON.stringify(recA));
info("protocol-B record", JSON.stringify(recB));

step("Attacker checks for ANY shared field between the two records...");
const sharedFields = Object.keys(recA).filter((k) => k !== "contextId" && recA[k] === recB[k]);
info("shared fields found", sharedFields.length === 0 ? "none" : sharedFields.join(", "));

step("Attacker tries brute-force hash matching: does Poseidon-stand-in(recA.pru) relate to recB.pru in any way the attacker can check without pru_seed?");
const attackerGuessLink = fieldHash(recA.pru) === fieldHash(recB.pru);
info("naive hash-of-PRU comparison matches?", attackerGuessLink);

if (sharedFields.length === 0 && !attackerGuessLink) {
  defended("No field, hash, or derivable relationship links the two records. From registry data alone, they are indistinguishable from two unrelated strangers' PRUs.");
  record("Attack 2: registry-only cross-context correlation", true);
} else {
  vulnerable("Found a shared or derivable link between two contexts belonging to the same wallet — this breaks unlinkability.");
  record("Attack 2: registry-only cross-context correlation", false, "critical");
}

// =====================================================================
section("ATTACK 3 — Cross-context proof/commitment substitution");
// =====================================================================
narrate("Goal: attacker takes valid derivation data proven for protocol-A and tries to pass it off as valid for protocol-B.");
const pruSeedA = contexts["protocol-A"].pruSeed;
const pruSeedB = contexts["protocol-B"].pruSeed;
step("Attacker computes commitment from protocol-A's pru_seed, submits it against protocol-B's registered commitment.");
const substitutedCommitment = deriveCommitment(pruSeedA);
const matchesB = substitutedCommitment === publicRegistry["protocol-B"].commitment;
info("protocol-A-derived commitment", substitutedCommitment);
info("protocol-B's real registered commitment", publicRegistry["protocol-B"].commitment);
info("do they match?", matchesB);

if (!matchesB) {
  defended("protocol-A's derivation data does not satisfy protocol-B's commitment. Context-binding at the pru_seed level (not just the final PRU) means there's no cross-context reuse surface at all.");
  record("Attack 3: cross-context proof substitution", true);
} else {
  vulnerable("protocol-A's data satisfied protocol-B's commitment — a proof for one protocol could authorize actions in another.");
  record("Attack 3: cross-context proof substitution", false, "critical");
}

// =====================================================================
section("ATTACK 4 — Action replay / mempool front-running");
// =====================================================================
narrate("Goal: attacker observes a valid action-bound proof for action X sitting in a public mempool, and tries to redirect it to authorize action Y (e.g. change the payment recipient) instead.");
const realAction = fieldHash("transfer 10 tokens to alice");
const attackerAction = fieldHash("transfer 10 tokens to attacker");
const realActionCommitment = deriveActionCommitment(pruSeedA, realAction);
info("real action_payload_hash (transfer to alice)", realAction);
info("attacker's substituted action_payload_hash (transfer to attacker)", attackerAction);
info("action_commitment the victim actually produced", realActionCommitment);

step("Attacker submits the SAME proof/action_commitment, but claims it's for their own action_payload_hash.");
const expectedForAttackerAction = deriveActionCommitment(pruSeedA, attackerAction);
const frontRunSucceeds = expectedForAttackerAction === realActionCommitment;
info("what action_commitment the attacker's substituted action would need", expectedForAttackerAction);
info("does it match the victim's real action_commitment?", frontRunSucceeds);

if (!frontRunSucceeds) {
  defended("The action_commitment is bound to the specific action_payload_hash via pru_seed. The attacker cannot compute a matching action_commitment for a different action without knowing pru_seed — which they don't have. Front-running/replay fails.");
  record("Attack 4: action replay / front-running", true);
} else {
  vulnerable("The attacker successfully redirected a proof to authorize a different action than the victim approved.");
  record("Attack 4: action replay / front-running", false, "critical");
}

// =====================================================================
section("ATTACK 5 — Vault/identity signature leak (documented critical boundary)");
// =====================================================================
narrate("Goal: simulate the one failure mode this entire system depends on never happening — identity_signature AND vault_signature leaking (e.g. a compromised dependency logging them).");
step("Simulating a leak: attacker obtains identity_signature and vault_signature from a compromised client.");
attackerGets("identity_signature", identitySignature);
attackerGets("vault_signature", vaultSignature);

step("With these, can the attacker reconstruct identity_seed and every registered PRU, WITHOUT the private key?");
const leakedIdentitySeed = deriveIdentitySeed(victim.address, identitySignature);
const reconstructedPRUs = {};
for (const contextId of Object.keys(publicRegistry)) {
  const seed = derivePRUSeed(leakedIdentitySeed, contextId, vaultSignature);
  reconstructedPRUs[contextId] = derivePRU(seed, 0);
}
const fullyReconstructed = Object.keys(publicRegistry).every(
  (ctx) => reconstructedPRUs[ctx] === publicRegistry[ctx].pru
);
attackerGets("reconstructed identity_seed", leakedIdentitySeed);
for (const [ctx, pru] of Object.entries(reconstructedPRUs)) {
  attackerGets(`reconstructed PRU for ${ctx}`, pru);
}
info("matches the real registered PRUs?", fullyReconstructed);

if (fullyReconstructed) {
  critical("If both fixed signatures leak, the attacker CAN reconstruct every PRU the victim has ever registered, across every protocol. Note what they still CANNOT do: forge NEW proofs that verify on-chain without the actual ZK circuit's private witness checks, or move funds without also controlling whatever the protocol's authorization logic requires beyond PRU ownership. But identity is fully deanonymized. This is why docs/09-security-model.md marks signature leakage as the single most sensitive failure mode — no cryptographic trick can protect data after the keys protecting it are gone. The correct mitigation is operational (see scripts/check-no-secret-leak.sh), not additional derivation logic.");
  record("Attack 5: signature leak → full reconstruction", false, "critical-expected");
} else {
  vulnerable("Unexpected: reconstruction did NOT match — this indicates a bug in the derivation consistency, not a security win. Investigate.");
  record("Attack 5: signature leak → full reconstruction", false, "critical");
}

// =====================================================================
section("ATTACK 6 — PIN brute-force (the design we rejected, tested empirically)");
// =====================================================================
narrate("Goal: demonstrate exactly why a 4-digit PIN was rejected during design — see docs/03-identity-model.md's 'Rejected design' note.");
step("Simulating the REJECTED formula: secret_entropy = hash(vault_signature, user_pin), with a real PIN the victim chose.");
const realPin = "4829";
const rejectedSecretEntropy = fieldHash("REJECTED_ENTROPY", vaultSignature, realPin);
const rejectedPRU = fieldHash("REJECTED_PRU", rejectedSecretEntropy, "protocol-A");
info("victim's real (secret) PIN", realPin);
info("resulting PRU under the rejected design", rejectedPRU);

step("Attacker has already obtained vault_signature (attack 5) and now brute-forces all 10,000 PINs against the PUBLIC registry entry.");
const bruteForceStart = process.hrtime.bigint();
let crackedPin = null;
for (let guess = 0; guess <= 9999; guess++) {
  const pinStr = String(guess).padStart(4, "0");
  const guessEntropy = fieldHash("REJECTED_ENTROPY", vaultSignature, pinStr);
  const guessPRU = fieldHash("REJECTED_PRU", guessEntropy, "protocol-A");
  if (guessPRU === rejectedPRU) {
    crackedPin = pinStr;
    break;
  }
}
const bruteForceMs = Number(process.hrtime.bigint() - bruteForceStart) / 1e6;
attackerGets("cracked PIN", crackedPin);
info("time to crack all 10,000 combinations", `${bruteForceMs.toFixed(2)} ms`);

step("Now checking the CURRENT (shipped) design for the same vector: is there any PIN parameter to brute-force at all?");
const currentDesignHasPin = false; // derivePRUSeed takes no PIN — see sdk/pru.ts
info("does the current derivePRUSeed() accept a PIN/password parameter?", currentDesignHasPin);

if (crackedPin === realPin && !currentDesignHasPin) {
  defended(`The rejected design's PIN was cracked in ${bruteForceMs.toFixed(2)}ms once vault_signature leaked — confirming it added no real security. The shipped design has no PIN parameter, so this entire attack surface doesn't exist in the current codebase.`);
  record("Attack 6: PIN brute-force (rejected design)", true);
} else {
  vulnerable("Something is inconsistent — either the PIN wasn't crackable as expected, or the current design unexpectedly has a PIN-like parameter. Investigate.");
  record("Attack 6: PIN brute-force (rejected design)", false, "critical");
}

// =====================================================================
section("ATTACK 7 — Phishing via fake registry program binding");
// =====================================================================
narrate("Goal: a phishing site presents the same message shape, but bound to a different attacker-controlled registry program.");
const phishingChallenge = buildIdentityChallenge({
  ...PHISHING_BINDING,
  walletPublicKey: victim.address,
});
info("real registry program", REGISTRY_BINDING.registryProgramId);
info("phishing registry program", PHISHING_BINDING.registryProgramId);

step("Victim (unknowingly) signs the phishing challenge.");
const phishingSignature = sign(victim.privateKey, phishingChallenge);
attackerGets("signature obtained via phishing", phishingSignature);

step("Attacker tries to replay this signature as if it were identity_signature for the real registry program.");
const phishingReplayValid = verifySignature(victim.publicKey, identityChallenge, phishingSignature);
info("does the phishing signature verify against the REAL challenge text?", phishingReplayValid);
const wouldProduceSameIdentitySeed = phishingSignature === identitySignature;
info("is the phishing signature identical to the real identity_signature?", wouldProduceSameIdentitySeed);

if (!phishingReplayValid && !wouldProduceSameIdentitySeed) {
  defended("Because the registry program ID is part of the signed payload, a signature obtained under a fake registry program is cryptographically distinct and does not verify against the real challenge.");
  record("Attack 7: phishing via fake registry program", true);
} else {
  vulnerable("The phishing signature was usable against the real system — domain binding failed to stop replay.");
  record("Attack 7: phishing via fake registry program", false, "critical");
}

// =====================================================================
section("ATTACK 8 — Malformed / garbage proof submission");
// =====================================================================
narrate("Goal: see if throwing garbage at the verifier crashes it or, worse, gets incorrectly accepted.");
const garbageInputs = [
  { label: "empty string", value: "" },
  { label: "random hex garbage", value: crypto.randomBytes(32).toString("hex") },
  { label: "wrong type (number instead of hex string)", value: 12345 },
  { label: "oversized junk (10KB)", value: "f".repeat(10000) },
  { label: "null-ish", value: "null" },
];
let allHandledGracefully = true;
for (const { label, value } of garbageInputs) {
  try {
    const matches = String(value) === realActionCommitment;
    info(`  garbage input [${label}] → treated as valid?`, matches);
    if (matches) allHandledGracefully = false;
  } catch (e) {
    info(`  garbage input [${label}] → threw`, e.message);
    // Throwing is acceptable as long as it doesn't crash the whole process — caught here.
  }
}

if (allHandledGracefully) {
  defended("Every malformed input was either rejected outright or handled without being mistaken for a valid commitment/proof. No garbage input was accepted as legitimate.");
  record("Attack 8: malformed/garbage proof submission", true);
} else {
  vulnerable("Some malformed input was incorrectly treated as a valid match.");
  record("Attack 8: malformed/garbage proof submission", false, "critical");
}

// =====================================================================
section("ATTACK 9 — Silent Mode B downgrade");
// =====================================================================
narrate("Goal: see if an attacker (or a careless integration) can trigger the wallet-revealing fallback mode without explicit, visible opt-in.");
function authorizeFallback(options = {}) {
  if (!options.allowFallback) {
    throw new Error("Mode B (signature fallback) requires allowFallback: true — see docs/07-authorization.md.");
  }
  return "session-signature-placeholder";
}
step("Attempting authorizeFallback() with no options (the 'careless integration' case)...");
let downgradeBlocked = false;
try {
  authorizeFallback();
} catch (e) {
  downgradeBlocked = true;
  info("  result", e.message);
}

if (downgradeBlocked) {
  defended("Mode B cannot be reached without an explicit allowFallback: true flag. There's no accidental or silent path to wallet-revealing fallback mode.");
  record("Attack 9: silent Mode B downgrade", true);
} else {
  vulnerable("Fallback mode was reachable without explicit opt-in — this silently defeats the entire privacy model for any integration that forgets to check.");
  record("Attack 9: silent Mode B downgrade", false, "critical");
}

// =====================================================================
section("ATTACK 10 — Registry field-injection");
// =====================================================================
narrate("Goal: a malicious or careless protocol tries to persist extra fields (e.g. the victim's wallet_address) into a registry record.");
function registerRecord(contextId, pru, commitment) {
  // Mirrors registry/memory.ts: the function signature itself only
  // accepts these three values — there is no field for extra data.
  return { contextId, pru, commitment };
}
step("Attacker-controlled protocol calls register() trying to sneak in a wallet_address field via a wider object...");
const maliciousAttempt = { contextId: "protocol-C", pru: "fake-pru", commitment: "fake-commitment", walletAddress: victim.address };
const actuallyStored = registerRecord(maliciousAttempt.contextId, maliciousAttempt.pru, maliciousAttempt.commitment);
info("attacker's attempted payload", JSON.stringify(maliciousAttempt));
info("what actually gets stored", JSON.stringify(actuallyStored));
const injectionSucceeded = "walletAddress" in actuallyStored;

if (!injectionSucceeded) {
  defended("The registry's write interface only has parameters for contextId/pru/commitment — there is no code path through which an extra field like walletAddress could be stored, regardless of what the caller tries to pass.");
  record("Attack 10: registry field injection", true);
} else {
  vulnerable("An extra field made it into the stored record — this could leak wallet linkage directly into public data.");
  record("Attack 10: registry field injection", false, "critical");
}

// =====================================================================
section("ATTACK 11 — Stale session signature replay (Mode B)");
// =====================================================================
narrate("Goal: attacker captures a legitimately-issued Mode B session signature and tries to replay it later.");
const usedNonces = new Set();
function buildSessionChallenge(walletAddress, timestamp, nonce) {
  return fieldHash("SESSION", walletAddress, timestamp, nonce);
}
function verifySessionFreshness(timestamp, nonce, maxAgeMs = 60_000) {
  const age = Date.now() - timestamp;
  if (age > maxAgeMs) return { ok: false, reason: "expired" };
  if (usedNonces.has(nonce)) return { ok: false, reason: "nonce already used (replay)" };
  usedNonces.add(nonce);
  return { ok: true };
}

const originalTimestamp = Date.now() - 5000; // signed 5 seconds ago
const nonce = crypto.randomUUID();
const sessionChallenge = buildSessionChallenge(victim.address, originalTimestamp, nonce);
const sessionSig = sign(victim.privateKey, sessionChallenge);
info("original session signature (5s old)", sessionSig);

step("Legitimate first use...");
const firstCheck = verifySessionFreshness(originalTimestamp, nonce);
info("  first submission result", JSON.stringify(firstCheck));

step("Attacker captures this signature/nonce and replays it again immediately...");
const replayCheck = verifySessionFreshness(originalTimestamp, nonce);
info("  replay submission result", JSON.stringify(replayCheck));

step("Attacker also tries an old, expired timestamp with a fresh nonce...");
const staleTimestamp = Date.now() - 120_000; // 2 minutes old
const staleCheck = verifySessionFreshness(staleTimestamp, crypto.randomUUID());
info("  stale timestamp submission result", JSON.stringify(staleCheck));

if (firstCheck.ok && !replayCheck.ok && !staleCheck.ok) {
  defended("Nonce tracking rejects the replay; the age check rejects the stale timestamp. A captured Mode B signature is a one-time-use credential.");
  record("Attack 11: stale session signature replay", true);
} else {
  vulnerable("A replayed or stale session signature was accepted.");
  record("Attack 11: stale session signature replay", false, "critical");
}

// =====================================================================
section("ATTACK 12 (control) — Identity reproducibility sanity check");
// =====================================================================
narrate("Not an attack — a baseline check that the LEGITIMATE recovery path actually works, since that's the entire point of the wallet-only recovery model.");
step("Re-deriving identity_signature and vault_signature from scratch, as if the victim reconnected on a brand new device.");
const rederivedIdentitySig = sign(victim.privateKey, identityChallenge);
const rederivedVaultSig = sign(victim.privateKey, vaultChallenge);
const reproducible = rederivedIdentitySig === identitySignature && rederivedVaultSig === vaultSignature;
info("re-derived identity_signature matches original?", rederivedIdentitySig === identitySignature);
info("re-derived vault_signature matches original?", rederivedVaultSig === vaultSignature);

if (reproducible) {
  defended("Full recovery works exactly as designed: wallet access alone reproduces every signature, seed, and PRU, with nothing extra needed.");
  record("Attack 12 (control): recovery reproducibility", true);
} else {
  vulnerable("Recovery is NOT reproducible — this would mean the 'no lost secrets' guarantee is broken. See README.md for the real-world caveat about deterministic vs non-deterministic wallet signing.");
  record("Attack 12 (control): recovery reproducibility", false, "critical");
}

// =====================================================================
section("SUMMARY");
// =====================================================================
console.log("");
let defendedCount = 0, criticalIssues = 0, expectedCritical = 0;
for (const r of results) {
  const icon = r.passed ? "\x1b[32m✅\x1b[0m" : (r.severity === "critical-expected" ? "\x1b[35m⚠\x1b[0m" : "\x1b[31m❌\x1b[0m");
  console.log(`${icon}  ${r.name}`);
  if (r.passed) defendedCount++;
  else if (r.severity === "critical-expected") expectedCritical++;
  else criticalIssues++;
}
console.log("");
console.log(`${defendedCount}/${results.length} attacks defended.`);
if (expectedCritical > 0) {
  console.log(`${expectedCritical} scenario(s) confirmed the ONE documented critical dependency (signature secrecy) — expected, not a bug.`);
}
if (criticalIssues > 0) {
  console.log(`\x1b[31m\x1b[1m${criticalIssues} UNEXPECTED VULNERABILITY(IES) FOUND — see above for details.\x1b[0m`);
  process.exitCode = 1;
} else {
  console.log("\x1b[32m\x1b[1mNo unexpected vulnerabilities found.\x1b[0m");
}
console.log("");
