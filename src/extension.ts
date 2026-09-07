import * as vscode from 'vscode';
import { verifySignature, HmacAlgorithm, HmacEncoding } from './hmac';

function getWebviewHtml(): string {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  body { font-family: var(--vscode-font-family); padding: 12px; color: var(--vscode-foreground); }
  label { display: block; margin-top: 10px; font-weight: 600; }
  textarea, input, select { width: 100%; box-sizing: border-box; margin-top: 4px; padding: 6px;
    background: var(--vscode-input-background); color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border); font-family: var(--vscode-editor-font-family); }
  textarea { min-height: 90px; }
  .row { display: flex; gap: 10px; }
  .row > div { flex: 1; }
  button { margin-top: 14px; padding: 8px 16px; background: var(--vscode-button-background);
    color: var(--vscode-button-foreground); border: none; cursor: pointer; }
  button:hover { background: var(--vscode-button-hoverBackground); }
  #result { margin-top: 14px; padding: 10px; border-radius: 4px; white-space: pre-wrap; font-family: var(--vscode-editor-font-family); }
  .match { background: rgba(80, 200, 120, 0.15); border: 1px solid #50c878; }
  .mismatch { background: rgba(220, 80, 80, 0.15); border: 1px solid #dc5050; }
</style>
</head>
<body>
  <label for="payload">Payload (raw request body, exactly as sent)</label>
  <textarea id="payload" placeholder='{"event":"push","ref":"main"}'></textarea>

  <label for="secret">Webhook secret</label>
  <input id="secret" type="text" placeholder="whsec_..." />

  <div class="row">
    <div>
      <label for="algorithm">Algorithm</label>
      <select id="algorithm">
        <option value="sha256" selected>sha256</option>
        <option value="sha1">sha1</option>
        <option value="sha512">sha512</option>
      </select>
    </div>
    <div>
      <label for="encoding">Encoding</label>
      <select id="encoding">
        <option value="hex" selected>hex</option>
        <option value="base64">base64</option>
      </select>
    </div>
  </div>

  <label for="received">Received signature (e.g. the X-Hub-Signature-256 header value -- "sha256=..." prefix is stripped automatically)</label>
  <input id="received" type="text" placeholder="sha256=..." />

  <button id="verify">Compute &amp; Verify</button>

  <div id="result" style="display:none"></div>

<script>
  const vscode = acquireVsCodeApi();
  document.getElementById('verify').addEventListener('click', () => {
    vscode.postMessage({
      type: 'verify',
      payload: document.getElementById('payload').value,
      secret: document.getElementById('secret').value,
      algorithm: document.getElementById('algorithm').value,
      encoding: document.getElementById('encoding').value,
      received: document.getElementById('received').value,
    });
  });
  window.addEventListener('message', (event) => {
    const msg = event.data;
    if (msg.type !== 'result') return;
    const el = document.getElementById('result');
    el.style.display = 'block';
    el.className = msg.matches ? 'match' : 'mismatch';
    el.textContent = 'Computed: ' + msg.computed + '\\n' + (msg.matches ? '✅ Matches the received signature.' : '❌ Does NOT match the received signature.');
  });
</script>
</body>
</html>`;
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('webhookSignatureCompanion.open', () => {
      const panel = vscode.window.createWebviewPanel(
        'webhookSignatureCompanion',
        'Webhook Signature Companion',
        vscode.ViewColumn.Active,
        { enableScripts: true },
      );
      panel.webview.html = getWebviewHtml();

      panel.webview.onDidReceiveMessage((message: { type: string; payload: string; secret: string; algorithm: HmacAlgorithm; encoding: HmacEncoding; received: string }) => {
        if (message.type !== 'verify') return;
        const result = verifySignature(message.payload, message.secret, message.algorithm, message.encoding, message.received);
        void panel.webview.postMessage({ type: 'result', computed: result.computed, matches: result.matches });
      });
    }),
  );
}

export function deactivate(): void {
  // no resources to release beyond what's registered in subscriptions
}
