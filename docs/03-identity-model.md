# Identity Model

## Goal

Generate and protect a `master_seed` that:

- Combines wallet identity binding with CSPRNG entropy
- Is encrypted with a wallet-derived key, so only that specific wallet can decrypt it
- Can be recovered using only wallet access
- Never needs to be stored in plaintext
- Is NOT derivable from a stolen signature alone (requires the encrypted random component)

## The Critical Security Improvement

**OLD (VULNERABLE):**
```
identity_seed = Poseidon(wallet_address, identity_signature)
PRU_seed = Poseidon(identity_seed, ...)  // Direct derivation
```
If attacker gets you to sign the same message → they get your identity_seed → all PRUs

**NEW (SECURE):**
```
identity_seed = Poseidon(wallet_address, identity_signature)  // From wallet
random_entropy = CSPRNG(32 bytes)  // Generated locally
master_seed = Poseidon(identity_seed, random_entropy)
PRU_seed = Poseidon(master_seed, ...)
```
- A stolen signature gives you `identity_seed`, but NOT `master_seed`
- The `random_entropy` is stored encrypted in the blob, not derivable from signatures
- To recover, you need BOTH the encrypted blob AND wallet access

**The key insight:** The master seed combines:
1. **Wallet identity binding** via `identity_seed` (from wallet signature)
2. **CSPRNG entropy** via `random_entropy` (stored encrypted)

This provides defense-in-depth: even if a signature is stolen, the attacker cannot derive `master_seed` without `random_entropy` which is encrypted in the blob.

## How It Works

### Step 1: Vault Initialization (one-time)

```
1. CSPRNG generates random_entropy locally (32 bytes)
2. User signs unique challenge (timestamp + nonce)
3. Wallet key derived from signature + wallet public key
4. identity_seed derived from wallet signature (provides wallet binding)
5. master_seed = Poseidon(identity_seed, random_entropy)
6. random_entropy encrypted with AES-256-GCM using wallet key
7. Encrypted blob stored in user's vault/TIN account
8. Plaintext master_seed and random_entropy held in memory only
```

```ts
// On device - generate random entropy
const randomEntropy = crypto.getRandomValues(new Uint8Array(32));

// Sign unique challenge
const { timestamp, nonce, message } = buildVaultChallenge(wallet, binding);
const signature = await wallet.signMessage(message);

// Derive identity_seed from wallet signature (provides wallet binding)
const identitySeed = Poseidon(walletPublicKey, signature);

// Derive wallet key from signature + wallet public key
const walletKey = Poseidon(walletPublicKey, signature);

// Combine identity_seed + random_entropy to create master_seed
const masterSeed = Poseidon(identitySeed, randomEntropy);

// Encrypt random_entropy (the secret component) with wallet key
const encryptedEntropy = await AES_256_GCM.encrypt(randomEntropy, walletKey);

// Store encrypted blob - requires THIS wallet to decrypt
await storage.save({ 
  encryptedEntropy, 
  walletPubkeyHash: hash(walletPublicKey), // For lookup
  ... 
});
```

### Step 2: Vault Unlock (per session)

```
1. Load encrypted blob from storage
2. System generates unique recovery challenge
3. User signs the challenge with the SAME wallet
4. Wallet key derived from signature + wallet public key
5. Decrypt random_entropy locally on device
6. Derive identity_seed from wallet signature
7. Derive master_seed = Poseidon(identity_seed, random_entropy)
8. User can now derive ALL their PRUs for ALL protocols
```

```ts
// Load encrypted blob
const blob = await storage.load();

// Generate recovery challenge
const challenge = buildRecoveryChallenge(wallet, binding);
const signature = await wallet.signMessage(challenge);

// Derive wallet key (MUST use the same wallet that encrypted)
const walletKey = Poseidon(walletPublicKey, signature);

// Decrypt random_entropy
const randomEntropy = await AES_256_GCM.decrypt(blob.encryptedEntropy, walletKey);

// Derive identity_seed from wallet (for wallet binding)
const identitySeed = Poseidon(walletPublicKey, signature);

// Reconstruct master_seed
const masterSeed = Poseidon(identitySeed, randomEntropy);

// Now user can derive PRUs for ANY protocol/purpose
const pruSeed = derivePRUSeed(masterSeed, "defi-xyz", "lending");
```

### Step 3: Derive PRUs for Any Protocol

```
After unlock, user can derive PRUs for ANY protocol:

PRU_seed[protocol_id][purpose] = Poseidon(master_seed, protocol_id, purpose)

The protocol_id is just a namespace - the master seed contains ALL the entropy.
User does NOT need the protocol to recover their PRUs.
```

This is crucial: if a protocol disappears, the user can still access their funds by:
1. Decrypting random_entropy with their wallet
2. Deriving identity_seed from wallet signature
3. Combining them to get master_seed
4. Deriving PRUs for the protocol they used
5. Using those PRUs to access their funds

### Step 4: Vault Lock (session end)

```
1. master_seed wiped from memory
2. random_entropy wiped from memory
3. No persistent storage of plaintext secrets
```

## Why This Design Works

### Security: Signature Theft Doesn't Compromise Identity

Even if an attacker steals your wallet signature:
1. They can derive `identity_seed = Poseidon(wallet_address, signature)`
2. They CANNOT derive `master_seed` because they don't have `random_entropy`
3. The `random_entropy` is encrypted in the blob, stored in your vault
4. Without the blob, the signature is useless

The relationship is:
```
signature → identity_seed (known if signature stolen)
signature → wallet_key (known if signature stolen)
BUT:
random_entropy → ONLY in encrypted blob
master_seed = Poseidon(identity_seed, random_entropy) ← CANNOT derive without random_entropy
```

### Recovery: Requires Both Components

The user can recover ALL their PRUs using:
1. Their wallet (to decrypt the blob AND derive identity_seed)
2. The encrypted blob (containing random_entropy)
3. Knowledge of which protocol_ids and purposes they used

## Handling Rules

- `master_seed` exists only in memory during active use
- `random_entropy` exists only in memory during active use
- `wallet_key` exists only in memory during encryption/decryption
- Encrypted blob is safe to store anywhere (TIN account, personal vault, cloud storage)
- The registry never stores master_seed, wallet_key, random_entropy, or any derivable secret
- A stolen signature alone cannot compromise the identity (requires the encrypted blob)
- The encrypted blob is bound to a specific wallet - only that wallet can decrypt it

## Session Signature (Mode B Fallback)

Session signatures are separate from identity derivation and encryption.

```ts
session_challenge = Poseidon("ZK-PRU-VAULT", wallet_public_key, timestamp, nonce)
```

They are used only for explicit Mode B fallback authorization. They must never be used for encryption or identity derivation.

## Why This Design Is Better Than Pure CSPRNG

A pure CSPRNG master seed has a problem: if you lose access to your encrypted blob AND your wallet, you cannot recover anything.

With this design:
- The `identity_seed` component provides a recovery anchor: if you have wallet access, you can re-derive `identity_seed`
- Combined with the encrypted `random_entropy`, you can reconstruct `master_seed`
- The wallet binding is preserved through `identity_seed`
- This provides defense-in-depth: even with just wallet access (no blob), the identity_seed component is preserved for future recovery when the blob is found
