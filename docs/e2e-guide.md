# End-to-End Manual Testing Guide

Complete walkthrough for testing the zkLogin sybil protection system with a real Google account.

## Prerequisites

- **Aztec sandbox** installed (`aztec-up`)
- **Compiled contracts**: both `registry/contracts/jwks_registry` and `login/contracts/zk_login` compiled via `aztec compile`
- **Google Cloud OAuth client ID** with `http://localhost:5173` added as an authorized redirect URI
- **Node.js 20+**

## Step 1: Start the Aztec Sandbox

```bash
aztec start --sandbox
```

Wait until you see the sandbox is ready (RPC endpoint at `http://localhost:8080`).

## Step 2: Deploy Contracts

From the project root:

```bash
cd docs/scripts
npm install
npx tsx deploy.ts
```

This deploys both JwksRegistry and ZkLogin contracts. The output includes:

- Contract addresses
- `.env` snippets for both the monitor backend and webapp frontend

Save the output — you'll need the addresses and admin secret key for the next steps.

**Example output:**
```
============================================================
DEPLOYMENT COMPLETE
============================================================
  Admin Address:     0x1234...
  Admin Secret Key:  12345678...
  JwksRegistry:      0xabcd...
  ZkLogin:           0xef01...

--- registry/server/.env ---
NETWORK=local
REGISTRY_ADDRESS=0xabcd...
ADMIN_SECRET_KEY=12345678...

--- login/webapp/.env ---
VITE_NETWORK=local
VITE_REGISTRY_ADDRESS=0xabcd...
VITE_ZK_LOGIN_ADDRESS=0xef01...
VITE_GOOGLE_CLIENT_ID=<your-google-client-id>
============================================================
```

## Step 3: Start the JWKS Monitor

```bash
cd registry/server
cp .env.example .env
```

Edit `.env` with the values from the deploy step:
- `REGISTRY_ADDRESS` — from deploy output
- `ADMIN_SECRET_KEY` — from deploy output

Then start the monitor:

```bash
npm start
```

Wait for the first poll to complete. You should see output like:

```
JWKS Monitor started (polling every 300000ms)
--- Poll cycle start ---
Fetching JWKS for Google...
  Found 3 RSA/RS256 key(s) for Google
Fetching JWKS for Apple...
  Found 4 RSA/RS256 key(s) for Apple
Diff result: 7 to add, 0 to update, 0 unchanged
Submitting key: provider=1, kid="..."
...
--- Poll cycle end ---
```

## Step 4: Verify Keys On-Chain (Optional)

Confirm the monitor synced keys correctly:

```bash
cd docs/scripts
npx tsx check-keys.ts <registry-address>
```

Replace `<registry-address>` with the JwksRegistry address from the deploy step.

Expected output shows each Google key ID and its on-chain status:

```
Key ID: "abc123def"
  Kid Hash: 0x...
  On-chain: VALID
  Modulus limb[0]: 1a2b3c...
  Non-zero limbs: 18
```

## Step 5: Start the Webapp

```bash
cd login/webapp
cp .env.example .env
```

Edit `.env` with:
- `VITE_REGISTRY_ADDRESS` — from deploy output
- `VITE_ZK_LOGIN_ADDRESS` — from deploy output
- `VITE_GOOGLE_CLIENT_ID` — your Google OAuth client ID

Then start the dev server:

```bash
npm run dev
```

The app will be available at `http://localhost:5173`.

## Step 6: Bind Identity

1. Open `http://localhost:5173` in your browser
2. Click **"Connect Aztec Wallet"** — this creates an ephemeral Aztec account
3. Click **"Sign in with Google"** — redirects to Google OAuth consent screen
4. Authenticate with your Google account — you'll be redirected back with a JWT
5. The app generates a ZK proof and submits a `bind_account` transaction
6. Wait for the transaction to confirm — you should see **"Identity Bound!"**

## Step 7: Verify Sybil Resistance

### Same wallet, same account
- Refresh the page and reconnect your wallet
- The app should show **"Already bound"** — your address is already linked

### New wallet, same Google account
- Open an incognito/private window
- Connect a new wallet (creates a different Aztec address)
- Sign in with the **same** Google account
- The transaction should **fail** with "identity already bound" — the same Google `sub` claim produces the same nullifier, which was already consumed

This proves sybil resistance: one Google identity can only bind to one Aztec address.

## Troubleshooting

### "Contract's public bytecode has not been transpiled"
You compiled with `nargo compile` instead of `aztec compile`. Re-compile:
```bash
cd registry/contracts/jwks_registry && aztec compile .
cd login/contracts/zk_login && aztec compile .
```

### "Signing key not found" or empty modulus limbs
The JWKS monitor hasn't synced keys yet. Wait for the first poll cycle to complete (check monitor logs for "Poll cycle end").

### "identity already bound"
This is expected behavior — sybil resistance is working. The Google identity has already been bound to a different Aztec address. Use a different Google account or redeploy the ZkLogin contract.

### Nonce mismatch error
The OAuth session expired or the nonce randomness was lost. This can happen if you close the browser tab between initiating OAuth and completing the callback. Start the flow over from the beginning.

### Transaction timeout
Sandbox transactions can take 30-60 seconds. If a transaction seems stuck, check that the sandbox is still running (`aztec start --sandbox`).

### "Failed to fetch JWKS"
The monitor can't reach Google/Apple JWKS endpoints. Check your internet connection. If behind a proxy, configure `HTTP_PROXY`/`HTTPS_PROXY` environment variables.
