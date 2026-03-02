/**
 * Primus zkTLS test script.
 *
 * Runs a real Primus attestation against a JWKS endpoint to discover
 * the exact SDK output format. Use this to verify your Primus credentials
 * and examine the attestation structure before integrating with the registry.
 *
 * Usage:
 *   PRIMUS_APP_ID=xxx PRIMUS_APP_SECRET=yyy npx tsx src/primus-test.ts
 */

// @ts-expect-error — Primus SDK types may not be available
import { PrimusCoreTLS } from "@primuslabs/zktls-core-sdk";

async function main() {
  const appId = process.env.PRIMUS_APP_ID;
  const appSecret = process.env.PRIMUS_APP_SECRET;

  if (!appId || !appSecret) {
    console.error("Error: PRIMUS_APP_ID and PRIMUS_APP_SECRET must be set");
    process.exit(1);
  }

  console.log("Initializing Primus zkTLS SDK...");
  const zkTLS = new PrimusCoreTLS();
  await zkTLS.init(appId, appSecret);
  console.log("SDK initialized");

  // Define the attestation request for Google JWKS
  const request = {
    url: "https://www.googleapis.com/oauth2/v3/certs",
    method: "GET",
    header: {},
  };

  // Request attestation of the first key's kid and modulus
  const responseResolves = [
    { keyName: "kid", parsePath: "$.keys[0].kid" },
    { keyName: "n", parsePath: "$.keys[0].n" },
  ];

  console.log("Starting attestation...");
  console.log("  URL:", request.url);
  console.log("  Resolves:", responseResolves);

  try {
    const attestation = await zkTLS.startAttestation(
      zkTLS.generateRequestParams(request, responseResolves)
    );

    console.log("\n=== Attestation Result ===");
    console.log(JSON.stringify(attestation, null, 2));

    // Log key fields for integration
    console.log("\n=== Key Fields ===");
    if (attestation.attestorPubKey) {
      console.log("attestorPubKey:", attestation.attestorPubKey);
    }
    if (attestation.attestationHash) {
      console.log("attestationHash:", attestation.attestationHash);
    }
    if (attestation.signature) {
      console.log("signature:", attestation.signature);
    }
    if (attestation.data) {
      console.log("data:", attestation.data);
    }
  } catch (err) {
    console.error("Attestation failed:", err);
    process.exit(1);
  }
}

main();
