/**
 * Pure logic -- no `vscode` dependency. New niche (not a port from
 * the Kotlin catalog). Evidence: multiple standalone web tools
 * (WebhookRelay, MyDevTools, InventiveHQ) solve exactly this problem
 * -- "does this webhook payload actually match its signature header"
 * -- and none of them is a VS Code extension. Uses Node's built-in
 * `node:crypto` HMAC -- no third-party crypto library.
 *
 * v0.1 scope, honestly noted: covers the generic
 * `HMAC(secret, payload)` shape most webhook providers use (GitHub,
 * generic sha1/sha256/sha512, hex or base64 encoding), including
 * GitHub's `sha256=<hex>` prefix convention. Stripe's scheme is
 * structurally different (`HMAC(secret, "<timestamp>.<payload>")`,
 * multiple versioned signatures in one header) and isn't implemented
 * here -- a real, separate mechanism, not a corner cut silently.
 */

import { createHmac } from 'node:crypto';

export type HmacAlgorithm = 'sha1' | 'sha256' | 'sha512';
export type HmacEncoding = 'hex' | 'base64';

export function computeHmac(payload: string, secret: string, algorithm: HmacAlgorithm, encoding: HmacEncoding): string {
  return createHmac(algorithm, secret).update(payload, 'utf8').digest(encoding);
}

// Well-known prefixes real providers put in front of the raw digest
// in their signature header -- stripped before comparison so pasting
// the header value verbatim (e.g. GitHub's whole
// "X-Hub-Signature-256" value) works without the user having to trim
// it by hand first.
const KNOWN_PREFIXES = ['sha256=', 'sha1=', 'sha512='];

export function stripKnownPrefix(receivedSignature: string): string {
  const trimmed = receivedSignature.trim();
  for (const prefix of KNOWN_PREFIXES) {
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length);
  }
  return trimmed;
}

export interface VerificationResult {
  computed: string;
  matches: boolean;
}

/** Constant-time-ish comparison isn't the point here (this is a local
 * debugging tool, not a production verifier defending against timing
 * attacks against itself) -- a plain string comparison after
 * normalizing case is the right trade-off for a UI tool. */
export function verifySignature(
  payload: string,
  secret: string,
  algorithm: HmacAlgorithm,
  encoding: HmacEncoding,
  receivedSignature: string,
): VerificationResult {
  const computed = computeHmac(payload, secret, algorithm, encoding);
  const received = stripKnownPrefix(receivedSignature);
  const matches = encoding === 'hex' ? computed.toLowerCase() === received.toLowerCase() : computed === received;
  return { computed, matches };
}
