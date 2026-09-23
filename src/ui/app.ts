import { recoverPrivateKeyFromReusedNonce } from '../attack/nonce-reuse';
import {
  bytesToBigInt,
  bytesToHex,
  equalBytes,
} from '../sm2/bytes';
import { SM2_CURVE_HEX } from '../sm2/curve';
import {
  ANNEX_CIPHERTEXT,
  ANNEX_ENCRYPTION_MESSAGE,
  ANNEX_MESSAGE,
  ANNEX_NONCE,
  ANNEX_PRIVATE_KEY,
  ANNEX_PUBLIC_KEY,
  ANNEX_SIGNATURE,
} from '../sm2/fixtures';
import {
  decryptSm2,
  encryptSm2,
  serializeCiphertext,
  signSm2,
  verifySm2,
} from '../sm2/sm2';
import type {
  CiphertextOrder,
  IdentityDigestTrace,
  Sm2EncryptionResult,
  Sm2SignTrace,
} from '../sm2/types';
import {
  createIdentityDigestTrace,
  DEFAULT_SM2_ID,
} from '../sm2/zdigest';

type VerdictKind = 'idle' | 'pass' | 'fail' | 'alarm';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function required<T extends Element>(root: ParentNode, selector: string): T {
  const element = root.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Missing UI element: ${selector}`);
  }
  return element;
}

function setVerdict(element: HTMLElement, kind: VerdictKind, message: string): void {
  const labels: Record<VerdictKind, string> = {
    idle: 'WAIT',
    pass: 'PASS',
    fail: 'FAIL',
    alarm: 'ALARM',
  };
  const icons: Record<VerdictKind, string> = {
    idle: '○',
    pass: '✓',
    fail: '×',
    alarm: '!',
  };

  element.className = `verdict verdict-${kind}`;
  element.dataset.state = kind;
  element.replaceChildren();
  const icon = document.createElement('span');
  icon.className = 'verdict-icon';
  icon.setAttribute('aria-hidden', 'true');
  icon.textContent = icons[kind];
  const text = document.createElement('span');
  const strong = document.createElement('strong');
  strong.textContent = `${labels[kind]} — `;
  text.append(strong, message);
  element.append(icon, text);
}

function setHex(root: ParentNode, selector: string, bytes: Uint8Array): void {
  required<HTMLElement>(root, selector).textContent = bytesToHex(bytes);
}

function selectedOrder(select: HTMLSelectElement): CiphertextOrder {
  return select.value === 'C1C2C3' ? 'C1C2C3' : 'C1C3C2';
}

function renderIdentityTrace(container: HTMLElement, trace: IdentityDigestTrace): void {
  container.replaceChildren();
  for (const part of trace.parts) {
    const item = document.createElement('li');
    item.className = 'flow-part';
    item.dataset.part = part.label;

    const label = document.createElement('span');
    label.className = 'flow-label';
    label.textContent = part.label;
    const value = document.createElement('code');
    value.className = 'flow-value';
    value.textContent = bytesToHex(part.bytes) || '(empty)';
    item.append(label, value);

    if (part.label === 'ENTL') {
      const detail = document.createElement('span');
      detail.className = 'flow-detail';
      detail.textContent = `${bytesToBigInt(part.bytes)} identity bits`;
      item.append(detail);
    }

    container.append(item);
  }
}

function layoutMarkup(order: CiphertextOrder): string {
  const parts = order === 'C1C3C2' ? ['C1', 'C3', 'C2'] : ['C1', 'C2', 'C3'];
  return parts.map((part) => `<span class="layout-token layout-${part.toLowerCase()}">${part}</span>`).join('<span class="layout-join" aria-hidden="true">+</span>');
}

// [extension] point: add SM2 key exchange as a fourth gated pane here.
const APP_MARKUP = `
  <div class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">SM2 Forge</h1>
      <p class="cl-hero-sub">GB/T 32918 · GM/T 0003 · RFC 8998</p>
      <p class="cl-hero-desc">Run real SM2 signatures and encryption, inspect the identity prefix, and decode both ciphertext byte orders.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">Adopting a national crypto suite is not a curve swap. SM2 signatures bind an identity, and two valid ciphertext serializations can still break interoperability.</p>
    </aside>
  </div>

  <nav class="pane-nav" aria-label="SM2 Forge exhibits">
    <ol role="list">
      <li><button type="button" class="pane-tab is-active" data-pane-button="1" aria-current="step"><span>01</span> The Curve</button></li>
      <li><button type="button" class="pane-tab" data-pane-button="2" disabled><span>02</span> The Signature</button></li>
      <li><button type="button" class="pane-tab" data-pane-button="3" disabled><span>03</span> Ciphertext + Break</button></li>
    </ol>
  </nav>

  <main class="lab-main">
    <section class="pane" id="pane-curve" data-pane="1" aria-labelledby="curve-title" tabindex="-1">
      <div class="pane-intro">
        <p class="eyebrow">COMPLIANCE GATE 01</p>
        <h2 id="curve-title">Build the specified curve before trusting the exhibit</h2>
        <p>SM2 is a public-key system standardized in China for signatures, encryption, and key exchange. This lab uses its required 256-bit prime-field curve, then checks the published signature and encryption examples before exposing any controls.</p>
      </div>
      <div class="curve-grid">
        <div class="parameter-panel">
          <div class="panel-heading"><h3 id="parameter-title">curveSM2 parameters</h3><span>RFC 8998 §3.2.1</span></div>
          <dl class="parameter-list">
            <div><dt>p</dt><dd><code>${SM2_CURVE_HEX.p}</code></dd></div>
            <div><dt>a</dt><dd><code>${SM2_CURVE_HEX.a}</code></dd></div>
            <div><dt>b</dt><dd><code>${SM2_CURVE_HEX.b}</code></dd></div>
            <div><dt>n</dt><dd><code>${SM2_CURVE_HEX.n}</code></dd></div>
            <div><dt>Gx</dt><dd><code>${SM2_CURVE_HEX.gx}</code></dd></div>
            <div><dt>Gy</dt><dd><code>${SM2_CURVE_HEX.gy}</code></dd></div>
            <div><dt>h</dt><dd><code>${SM2_CURVE_HEX.h}</code></dd></div>
          </dl>
        </div>
        <div class="gate-panel">
          <p class="eyebrow">KNOWN-ANSWER TESTS</p>
          <h3 id="kat-title">Annex A + Annex C</h3>
          <p>One fixed private key and nonce must reproduce the standards' bytes exactly. A round-trip alone is not enough.</p>
          <button type="button" class="button button-primary" id="run-kats">Run published vectors</button>
          <div class="gate-results" aria-live="polite">
            <div class="verdict verdict-idle" id="signature-kat" data-state="idle"><span class="verdict-icon" aria-hidden="true">○</span><span><strong>WAIT — </strong>Annex A has not run.</span></div>
            <div class="verdict verdict-idle" id="encryption-kat" data-state="idle"><span class="verdict-icon" aria-hidden="true">○</span><span><strong>WAIT — </strong>Annex C has not run.</span></div>
          </div>
          <button type="button" class="button button-secondary continue-button" id="continue-signature" disabled>Continue to the identity digest</button>
        </div>
      </div>
    </section>

    <section class="pane" id="pane-signature" data-pane="2" aria-labelledby="signature-title" tabindex="-1" hidden>
      <div class="pane-intro">
        <p class="eyebrow">HEADLINE MECHANISM 02</p>
        <h2 id="signature-title">The identity enters the hash before the message</h2>
        <p>SM2 computes a digest called Z_A from the signer's identity, curve parameters, and public key. The verifier must rebuild the same Z_A, so an otherwise unchanged signature fails under a different identity.</p>
      </div>
      <div class="signature-workbench">
        <form class="control-panel" id="signature-form">
          <div class="control">
            <label for="signer-id">Signer identity</label>
            <input id="signer-id" name="signer-id" type="text" value="merchant@example.cn" maxlength="256" autocomplete="off" />
            <span class="control-note">UTF-8 bytes; empty is valid. ENTL records this value's bit length.</span>
          </div>
          <div class="control">
            <label for="signature-message">Message</label>
            <textarea id="signature-message" name="signature-message" rows="3">Transfer 25 units</textarea>
          </div>
          <button type="submit" class="button button-primary">Build Z_A and sign</button>
          <div class="retired-status" id="signature-retired" role="status" aria-live="polite" hidden></div>
        </form>

        <div class="signature-output" id="signature-output" hidden>
          <div class="mechanism-header"><span>SM3 input</span><strong>ENTL || ID || a || b || Gx || Gy || xA || yA</strong></div>
          <ol class="identity-flow" id="identity-flow" role="list" aria-label="Z A digest input parts"></ol>
          <div class="digest-line">
            <span>SM3</span><span aria-hidden="true">→</span><code id="za-digest"></code>
          </div>
          <div class="message-hash-flow" role="group" aria-label="Z A digest concatenated with the message and hashed to e">
            <span class="hash-token">Z_A</span><span aria-hidden="true">||</span><code id="message-bytes"></code><span class="hash-arrow">SM3 → e</span><code id="message-digest"></code>
          </div>
          <div class="signature-bytes">
            <div><span>r</span><code id="signature-r"></code></div>
            <div><span>s</span><code id="signature-s"></code></div>
          </div>

          <fieldset class="verifier-choice">
            <legend>Verifier identity</legend>
            <label><input type="radio" name="verifier-id" value="same" checked /> Use the signer's current ID</label>
            <label><input type="radio" name="verifier-id" value="default" /> Use RFC default <code>1234567812345678</code></label>
          </fieldset>
          <div class="verdict verdict-idle sticky-verdict" id="identity-verdict" data-state="idle" role="status" aria-live="polite"><span class="verdict-icon" aria-hidden="true">○</span><span><strong>WAIT — </strong>Select a verifier identity.</span></div>
          <div class="sticky-failure" id="identity-failure-log" role="log" aria-live="polite" hidden></div>

          <details class="equation-details">
            <summary>Signature equation</summary>
            <p><code>e = SM3(Z_A || message)</code></p>
            <p><code>r = (e + x₁) mod n</code></p>
            <p><code>s = (1 + d)⁻¹(k − r·d) mod n</code></p>
          </details>
          <button type="button" class="button button-secondary continue-button" id="continue-ciphertext" disabled>Continue to ciphertext and nonce reuse</button>
        </div>
      </div>
    </section>

    <section class="pane" id="pane-ciphertext" data-pane="3" aria-labelledby="ciphertext-title" tabindex="-1" hidden>
      <div class="pane-intro">
        <p class="eyebrow">INTEROPERABILITY + FAILURE 03</p>
        <h2 id="ciphertext-title">Same cryptogram, two byte orders, one fatal signing mistake</h2>
        <p>SM2 encryption produces a curve point C1, encrypted payload C2, and SM3 integrity digest C3. Standards and older implementations serialize those same components in different orders.</p>
      </div>

      <section class="exhibit" aria-labelledby="orders-title">
        <div class="exhibit-heading"><div><p class="eyebrow">BYTE-ORDER LAB</p><h3 id="orders-title">Encrypt once, regroup the same components</h3></div><span class="source-chip">GB/T order + early-draft order</span></div>
        <div class="control-row">
          <div class="control control-grow"><label for="encryption-message">Plaintext</label><input id="encryption-message" type="text" value="encryption standard" /></div>
          <button type="button" class="button button-primary" id="encrypt-once">Encrypt once</button>
        </div>
        <div class="retired-status" id="encryption-retired" role="status" aria-live="polite" hidden></div>
        <div id="order-output" hidden>
          <div class="order-cards">
            <article class="order-card">
              <p class="order-source">GB/T 32918.4-2016</p><h4>C1C3C2</h4>
              <div class="layout-strip">${layoutMarkup('C1C3C2')}</div>
              <div class="verdict verdict-idle" id="roundtrip-c1c3c2" data-state="idle"><span class="verdict-icon" aria-hidden="true">○</span><span><strong>WAIT — </strong>Not checked.</span></div>
            </article>
            <article class="order-card">
              <p class="order-source">Earlier draft serialization</p><h4>C1C2C3</h4>
              <div class="layout-strip">${layoutMarkup('C1C2C3')}</div>
              <div class="verdict verdict-idle" id="roundtrip-c1c2c3" data-state="idle"><span class="verdict-icon" aria-hidden="true">○</span><span><strong>WAIT — </strong>Not checked.</span></div>
            </article>
          </div>
          <div class="component-inspector">
            <div><span>C1 · curve point</span><code id="component-c1"></code></div>
            <div><span>C3 · integrity digest</span><code id="component-c3"></code></div>
            <div><span>C2 · encrypted payload</span><code id="component-c2"></code></div>
          </div>
          <div class="decoder-bench">
            <div class="control"><label for="wire-order">Bytes sent on the wire</label><select id="wire-order"><option value="C1C3C2">C1C3C2 · GB/T 32918.4</option><option value="C1C2C3">C1C2C3 · earlier draft</option></select></div>
            <div class="control"><label for="decoder-order">Decoder expects</label><select id="decoder-order"><option value="C1C3C2">C1C3C2 · GB/T 32918.4</option><option value="C1C2C3">C1C2C3 · earlier draft</option></select></div>
            <button type="button" class="button button-secondary" id="run-decoder">Feed bytes to decoder</button>
          </div>
          <div class="verdict verdict-idle sticky-verdict" id="order-verdict" data-state="idle" role="status" aria-live="polite"><span class="verdict-icon" aria-hidden="true">○</span><span><strong>WAIT — </strong>Select a wire and decoder order.</span></div>
          <div class="sticky-failure" id="order-failure-log" role="log" aria-live="polite" hidden></div>
          <p class="negative-claim" id="order-negative-claim">Both layouts protect the same plaintext when the decoder matches. The mismatch is an interoperability failure, not a weakness in the SM2 curve or encryption equations.</p>
        </div>
      </section>

      <section class="exhibit attack-exhibit" aria-labelledby="attack-title">
        <div class="exhibit-heading"><div><p class="eyebrow danger-eyebrow">DELIBERATELY BROKEN PATH</p><h3 id="attack-title">Reuse one signing nonce and recover the private key</h3></div><span class="broken-chip">BROKEN MODE</span></div>
        <p>This control bypasses normal random nonce generation only inside the isolated attack module. It signs two messages with the same k, asks the real verifier to accept both, then solves the two equations for d.</p>
        <div class="attack-controls">
          <div class="control"><label for="attack-message-one">Message 1</label><input id="attack-message-one" type="text" value="Approve invoice 1042" /></div>
          <div class="control"><label for="attack-message-two">Message 2</label><input id="attack-message-two" type="text" value="Approve invoice 9001" /></div>
          <button type="button" class="button button-danger" id="run-attack">Reuse k, sign twice, recover d</button>
        </div>
        <div class="attack-output" id="attack-output" hidden>
          <div class="signature-pair">
            <article><h4>Signature 1</h4><div class="verdict verdict-idle" id="attack-verify-one" data-state="idle"></div><code id="attack-signature-one"></code></article>
            <article><h4>Signature 2</h4><div class="verdict verdict-idle" id="attack-verify-two" data-state="idle"></div><code id="attack-signature-two"></code></article>
          </div>
          <div class="recovery-equation"><code>d = (s₂ − s₁) · ((r₁ + s₁) − (r₂ + s₂))⁻¹ mod n</code></div>
          <div class="recovered-key"><span>Recovered d</span><code id="recovered-private-key"></code></div>
          <div class="verdict verdict-idle sticky-verdict" id="recovery-verdict" data-state="idle" role="status" aria-live="polite"></div>
          <p class="negative-claim" id="nonce-negative-claim">Both signatures can be mathematically valid while the signing process is catastrophically unsafe. SM2 nonce reuse is as fatal as ECDSA nonce reuse: verification does not prove the nonce generator protected the private key. This attacks the signing process, not curveSM2.</p>
        </div>
      </section>

      <div class="real-world">
        <p class="eyebrow">REAL-WORLD CONTEXT</p><h3 id="real-world-title">RFC 8998 ShangMi TLS 1.3 profile</h3>
        <dl><div><dt>Cipher suites</dt><dd><code>TLS_SM4_GCM_SM3 0x00C6</code><br /><code>TLS_SM4_CCM_SM3 0x00C7</code></dd></div><div><dt>Signature scheme</dt><dd><code>sm2sig_sm3 0x0708</code></dd></div><div><dt>Supported group</dt><dd><code>curveSM2 41</code></dd></div></dl>
        <p>This lab does not implement TLS, SM2 key exchange, SM4, or SM3 internals, and it makes no claim that SM2 is stronger or weaker than ECDSA. It demonstrates SM2 signing and encryption only; it is not production cryptography.</p>
      </div>
    </section>
  </main>

  <div class="related-links">Related: <a href="https://systemslibrarian.github.io/crypto-lab-ecdsa-forge/">ECDSA Forge</a> · <a href="https://systemslibrarian.github.io/crypto-lab-schnorr-forge/">Schnorr Forge</a> · <a href="https://systemslibrarian.github.io/crypto-lab-tls-handshake/">TLS Handshake</a></div>
  <footer class="scripture-footer"><p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p></footer>
`;

export function renderApp(root: HTMLElement): void {
  root.innerHTML = APP_MARKUP;

  const paneButtons = Array.from(root.querySelectorAll<HTMLButtonElement>('[data-pane-button]'));
  const panes = Array.from(root.querySelectorAll<HTMLElement>('[data-pane]'));
  let unlockedPane = 1;

  function showPane(paneNumber: number): void {
    if (paneNumber > unlockedPane) {
      return;
    }
    for (const pane of panes) {
      pane.hidden = Number(pane.dataset.pane) !== paneNumber;
    }
    for (const button of paneButtons) {
      const active = Number(button.dataset.paneButton) === paneNumber;
      button.classList.toggle('is-active', active);
      if (active) {
        button.setAttribute('aria-current', 'step');
      } else {
        button.removeAttribute('aria-current');
      }
    }
    required<HTMLElement>(root, `[data-pane="${paneNumber}"]`).focus({ preventScroll: true });
  }

  function unlockPane(paneNumber: number): void {
    unlockedPane = Math.max(unlockedPane, paneNumber);
    const button = required<HTMLButtonElement>(root, `[data-pane-button="${paneNumber}"]`);
    button.disabled = false;
  }

  for (const button of paneButtons) {
    button.addEventListener('click', () => showPane(Number(button.dataset.paneButton)));
  }

  const runKats = required<HTMLButtonElement>(root, '#run-kats');
  const signatureKat = required<HTMLElement>(root, '#signature-kat');
  const encryptionKat = required<HTMLElement>(root, '#encryption-kat');
  const continueSignature = required<HTMLButtonElement>(root, '#continue-signature');

  runKats.addEventListener('click', () => {
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const signatureTrace = signSm2(ANNEX_PRIVATE_KEY, ANNEX_MESSAGE, { nonceSource: () => nonce });
    const signatureMatches =
      signatureTrace.signature.r === ANNEX_SIGNATURE.r &&
      signatureTrace.signature.s === ANNEX_SIGNATURE.s &&
      verifySm2(ANNEX_PUBLIC_KEY, ANNEX_MESSAGE, signatureTrace.signature).accepted;

    const encrypted = encryptSm2(ANNEX_PUBLIC_KEY, ANNEX_ENCRYPTION_MESSAGE, {
      order: 'C1C3C2',
      nonceSource: () => nonce,
    });
    const decrypted = decryptSm2(ANNEX_PRIVATE_KEY, encrypted.ciphertext, 'C1C3C2');
    const encryptionMatches =
      equalBytes(encrypted.c1, ANNEX_CIPHERTEXT.c1) &&
      equalBytes(encrypted.c2, ANNEX_CIPHERTEXT.c2) &&
      equalBytes(encrypted.c3, ANNEX_CIPHERTEXT.c3) &&
      decrypted.ok &&
      equalBytes(decrypted.plaintext, ANNEX_ENCRYPTION_MESSAGE);

    setVerdict(signatureKat, signatureMatches ? 'pass' : 'fail', signatureMatches ? 'Annex A r and s match byte-for-byte; the real verifier accepts.' : 'Annex A signature bytes differ. The next pane remains locked.');
    setVerdict(encryptionKat, encryptionMatches ? 'pass' : 'fail', encryptionMatches ? 'Annex C C1, C2, and C3 match byte-for-byte; decrypt returns the message.' : 'Annex C ciphertext differs. The next pane remains locked.');

    if (signatureMatches && encryptionMatches) {
      unlockPane(2);
      continueSignature.disabled = false;
    }
  });
  continueSignature.addEventListener('click', () => showPane(2));

  const signatureForm = required<HTMLFormElement>(root, '#signature-form');
  const signerId = required<HTMLInputElement>(root, '#signer-id');
  const signatureMessage = required<HTMLTextAreaElement>(root, '#signature-message');
  const signatureOutput = required<HTMLElement>(root, '#signature-output');
  const signatureRetired = required<HTMLElement>(root, '#signature-retired');
  const identityVerdict = required<HTMLElement>(root, '#identity-verdict');
  const identityFailureLog = required<HTMLElement>(root, '#identity-failure-log');
  const continueCiphertext = required<HTMLButtonElement>(root, '#continue-ciphertext');
  let activeSignature: { trace: Sm2SignTrace; identity: Uint8Array; idText: string; messageText: string } | undefined;

  function runIdentityVerifier(): void {
    if (!activeSignature) {
      return;
    }
    const mode = required<HTMLInputElement>(root, 'input[name="verifier-id"]:checked').value;
    const verifierIdentity = mode === 'same' ? activeSignature.identity : DEFAULT_SM2_ID;
    const result = verifySm2(
      activeSignature.trace.publicKey,
      encoder.encode(activeSignature.messageText),
      activeSignature.trace.signature,
      verifierIdentity,
    );
    const identityLabel = mode === 'same' ? 'the signer ID' : 'the RFC default ID';
    setVerdict(identityVerdict, result.accepted ? 'pass' : 'fail', result.accepted ? `Verifier accepts with ${identityLabel}; Z_A matches.` : `Verifier rejects with ${identityLabel}; it rebuilt a different Z_A.`);
    if (!result.accepted) {
      identityFailureLog.hidden = false;
      identityFailureLog.textContent = `Last observed failure — verifier used ${identityLabel} and rebuilt a different Z_A.`;
    }
  }

  function retireSignatureIfChanged(): void {
    if (!activeSignature) {
      return;
    }
    if (signerId.value === activeSignature.idText && signatureMessage.value === activeSignature.messageText) {
      return;
    }
    activeSignature = undefined;
    signatureOutput.hidden = true;
    signatureRetired.hidden = false;
    signatureRetired.textContent = 'Previous signature retired because the ID or message changed. Build Z_A again before verifying.';
  }

  signerId.addEventListener('input', retireSignatureIfChanged);
  signatureMessage.addEventListener('input', retireSignatureIfChanged);
  for (const verifierChoice of root.querySelectorAll<HTMLInputElement>('input[name="verifier-id"]')) {
    verifierChoice.addEventListener('change', runIdentityVerifier);
  }

  signatureForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const identity = encoder.encode(signerId.value);
    const message = encoder.encode(signatureMessage.value);
    const trace = signSm2(ANNEX_PRIVATE_KEY, message, { identity });
    const identityTrace = createIdentityDigestTrace(trace.publicKey, identity);
    activeSignature = { trace, identity, idText: signerId.value, messageText: signatureMessage.value };

    renderIdentityTrace(required<HTMLElement>(root, '#identity-flow'), identityTrace);
    setHex(root, '#za-digest', trace.identityDigest);
    setHex(root, '#message-bytes', message);
    setHex(root, '#message-digest', trace.messageDigest);
    required<HTMLElement>(root, '#signature-r').textContent = trace.signature.r.toString(16).padStart(64, '0');
    required<HTMLElement>(root, '#signature-s').textContent = trace.signature.s.toString(16).padStart(64, '0');
    signatureRetired.hidden = true;
    identityFailureLog.hidden = true;
    identityFailureLog.textContent = '';
    signatureOutput.hidden = false;
    runIdentityVerifier();

    if (verifySm2(trace.publicKey, message, trace.signature, identity).accepted) {
      unlockPane(3);
      continueCiphertext.disabled = false;
    }
  });
  continueCiphertext.addEventListener('click', () => showPane(3));

  const encryptionMessage = required<HTMLInputElement>(root, '#encryption-message');
  const encryptOnce = required<HTMLButtonElement>(root, '#encrypt-once');
  const orderOutput = required<HTMLElement>(root, '#order-output');
  const encryptionRetired = required<HTMLElement>(root, '#encryption-retired');
  const wireOrder = required<HTMLSelectElement>(root, '#wire-order');
  const decoderOrder = required<HTMLSelectElement>(root, '#decoder-order');
  const orderVerdict = required<HTMLElement>(root, '#order-verdict');
  const failureLog = required<HTMLElement>(root, '#order-failure-log');
  let activeEncryption: { result: Sm2EncryptionResult; plaintextText: string } | undefined;

  function runDecoder(): void {
    if (!activeEncryption) {
      return;
    }
    const wire = selectedOrder(wireOrder);
    const expected = selectedOrder(decoderOrder);
    const transmitted = serializeCiphertext(activeEncryption.result, wire);
    const result = decryptSm2(ANNEX_PRIVATE_KEY, transmitted, expected);

    if (result.ok) {
      const exact = decoder.decode(result.plaintext) === activeEncryption.plaintextText;
      setVerdict(orderVerdict, exact ? 'pass' : 'alarm', exact ? `Decoder accepted ${expected}; recovered plaintext matches byte-for-byte.` : 'Decoder returned different plaintext unexpectedly.');
      return;
    }

    const mismatch = wire !== expected;
    setVerdict(orderVerdict, 'fail', mismatch ? `ORDER MISMATCH: wire is ${wire}, decoder expects ${expected}. ${result.reason}` : result.reason);
    failureLog.hidden = false;
    failureLog.textContent = `Last observed failure — ${mismatch ? `wire ${wire} vs decoder ${expected}` : result.code}: ${result.reason}`;
  }

  encryptionMessage.addEventListener('input', () => {
    if (!activeEncryption || encryptionMessage.value === activeEncryption.plaintextText) {
      return;
    }
    activeEncryption = undefined;
    orderOutput.hidden = true;
    encryptionRetired.hidden = false;
    encryptionRetired.textContent = 'Previous ciphertext retired because the plaintext changed. Encrypt again before decoding.';
  });
  required<HTMLButtonElement>(root, '#run-decoder').addEventListener('click', runDecoder);
  wireOrder.addEventListener('change', runDecoder);
  decoderOrder.addEventListener('change', runDecoder);

  encryptOnce.addEventListener('click', () => {
    const plaintext = encoder.encode(encryptionMessage.value);
    const result = encryptSm2(ANNEX_PUBLIC_KEY, plaintext);
    activeEncryption = { result, plaintextText: encryptionMessage.value };
    setHex(root, '#component-c1', result.c1);
    setHex(root, '#component-c2', result.c2);
    setHex(root, '#component-c3', result.c3);

    for (const order of ['C1C3C2', 'C1C2C3'] as const) {
      const roundTrip = decryptSm2(ANNEX_PRIVATE_KEY, serializeCiphertext(result, order), order);
      const verdict = required<HTMLElement>(root, order === 'C1C3C2' ? '#roundtrip-c1c3c2' : '#roundtrip-c1c2c3');
      setVerdict(verdict, roundTrip.ok ? 'pass' : 'fail', roundTrip.ok ? 'Matching decoder round-trips.' : roundTrip.reason);
    }

    encryptionRetired.hidden = true;
    orderOutput.hidden = false;
    runDecoder();
  });

  const attackOutput = required<HTMLElement>(root, '#attack-output');
  required<HTMLButtonElement>(root, '#run-attack').addEventListener('click', () => {
    const firstMessage = encoder.encode(required<HTMLInputElement>(root, '#attack-message-one').value);
    const secondMessage = encoder.encode(required<HTMLInputElement>(root, '#attack-message-two').value);
    const nonce = bytesToBigInt(ANNEX_NONCE);
    const first = signSm2(ANNEX_PRIVATE_KEY, firstMessage, { nonceSource: () => nonce });
    const second = signSm2(ANNEX_PRIVATE_KEY, secondMessage, { nonceSource: () => nonce });
    const firstAccepted = verifySm2(ANNEX_PUBLIC_KEY, firstMessage, first.signature).accepted;
    const secondAccepted = verifySm2(ANNEX_PUBLIC_KEY, secondMessage, second.signature).accepted;
    const recovery = recoverPrivateKeyFromReusedNonce(first.signature, second.signature);

    setVerdict(required<HTMLElement>(root, '#attack-verify-one'), firstAccepted ? 'pass' : 'fail', firstAccepted ? 'Real verifier accepts signature 1.' : 'Verifier rejected signature 1.');
    setVerdict(required<HTMLElement>(root, '#attack-verify-two'), secondAccepted ? 'pass' : 'fail', secondAccepted ? 'Real verifier accepts signature 2.' : 'Verifier rejected signature 2.');
    required<HTMLElement>(root, '#attack-signature-one').textContent = `r=${first.signature.r.toString(16)}\ns=${first.signature.s.toString(16)}`;
    required<HTMLElement>(root, '#attack-signature-two').textContent = `r=${second.signature.r.toString(16)}\ns=${second.signature.s.toString(16)}`;

    const recoveredKey = required<HTMLElement>(root, '#recovered-private-key');
    const recoveryVerdict = required<HTMLElement>(root, '#recovery-verdict');
    if (recovery.recovered) {
      recoveredKey.textContent = recovery.privateKey.toString(16).padStart(64, '0');
      const publicKeyMatches = equalBytes(recovery.publicKey, ANNEX_PUBLIC_KEY);
      setVerdict(recoveryVerdict, publicKeyMatches ? 'alarm' : 'fail', publicKeyMatches ? 'RECOVERED d re-derives the victim public key byte-for-byte. Both valid signatures exposed the key.' : 'Recovered scalar did not derive the victim public key.');
    } else {
      recoveredKey.textContent = 'not recovered';
      setVerdict(recoveryVerdict, 'fail', recovery.reason);
    }
    attackOutput.hidden = false;
  });
}