# Webhook Signature Companion (VS Code)

Computes and verifies HMAC webhook signatures (GitHub-style
`sha256=`/`sha1=` prefix, generic sha1/sha256/sha512, hex or base64)
against a payload and secret — right in the editor. No data leaves
your editor.

**v0.1, new niche.** Not a port from the Gap Hunter Labs IntelliJ-
family catalog. Evidence: multiple standalone web tools (WebhookRelay,
MyDevTools, InventiveHQ) solve exactly this problem — none of them is
a VS Code extension, even though it's a debugging step any webhook
integration eventually needs.

## What it does

**Command: `Webhook Signature Companion: Compute & Verify`** — opens a
panel with fields for the raw payload, the secret, algorithm/encoding,
and the received signature (paste the whole header value — the
`sha256=` prefix is stripped automatically). Computes the HMAC using
Node's built-in `node:crypto` (no third-party crypto library) and
shows a clear match/mismatch verdict alongside the computed digest.

**v0.1 scope, honestly noted:** covers the generic
`HMAC(secret, payload)` shape most providers use (GitHub, and any
custom webhook implementation using the same convention). Stripe's
scheme is structurally different (`HMAC(secret, "<timestamp>.<payload>")`,
multiple versioned signatures in one header) and isn't implemented
here — a real, separate mechanism, not a corner cut silently.

## Privacy

See [PRIVACY.md](PRIVACY.md) — zero network calls. Payload and secret
you type are used only in-memory to compute the HMAC and are never
written to disk or sent anywhere.

## Development

```bash
npm install
npm run compile   # or: npm run watch
npm test
```

To build an installable package without publishing:

```bash
npx @vscode/vsce package
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
