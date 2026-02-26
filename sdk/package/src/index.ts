/**
 * @aztec-zklogin/sdk
 *
 * Privacy-preserving identity binding for Aztec.
 * Link a Google or Apple account to an Aztec address with ZK proofs.
 *
 * Usage:
 *
 *   import { ZkLogin } from "@aztec-zklogin/sdk";
 *
 *   const zkLogin = new ZkLogin({
 *     pxe: myPxe,
 *     wallet: myWallet,
 *     userAddress: myAddress,
 *     zkLoginAddress: "0x...",
 *     registryAddress: "0x...",
 *   });
 *
 *   // Check if already bound
 *   if (await zkLogin.isBound()) {
 *     console.log("Already bound!");
 *     return;
 *   }
 *
 *   // Start binding (redirects to OAuth provider)
 *   await zkLogin.startBind("google");
 *
 *   // On every page load, check for completed OAuth redirect
 *   const result = await zkLogin.completeBind();
 *   if (result) {
 *     console.log("Bound!", result.txHash);
 *   }
 */

export { ZkLogin } from "./zklogin.js";
export type {
  BindResult,
  Network,
  Provider,
  ZkLoginOptions,
} from "./types.js";
