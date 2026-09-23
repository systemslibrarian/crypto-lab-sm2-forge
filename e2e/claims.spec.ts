import { expect, test, type Page } from '@playwright/test';

async function unlockSignature(page: Page): Promise<void> {
  await page.goto('.');
  await page.getByRole('button', { name: 'Run published vectors' }).click();
  await expect(page.locator('#signature-kat')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#encryption-kat')).toHaveAttribute('data-state', 'pass');
  await page.getByRole('button', { name: 'Continue to the identity digest' }).click();
}

async function unlockCiphertext(page: Page): Promise<void> {
  await unlockSignature(page);
  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();
  await expect(page.locator('#identity-verdict')).toHaveAttribute('data-state', 'pass');
  await page.getByRole('button', { name: 'Continue to ciphertext and nonce reuse' }).click();
}

test('the displayed ENTL equals the displayed UTF-8 identity bit length', async ({ page }) => {
  await unlockSignature(page);
  const identity = 'A界';
  await page.getByLabel('Signer identity').fill(identity);
  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();

  const entlHex = await page.locator('[data-part="ENTL"] .flow-value').innerText();
  const displayedBits = Number.parseInt(entlHex, 16);
  const independentlyCountedBits = new TextEncoder().encode(identity).length * 8;
  expect(displayedBits).toBe(independentlyCountedBits);
  await expect(page.locator('[data-part="ENTL"] .flow-detail')).toHaveText(
    `${independentlyCountedBits} identity bits`,
  );
});

test('one signature accepts only when the verifier rebuilds the same Z_A', async ({ page }) => {
  await unlockSignature(page);
  await page.getByLabel('Signer identity').fill('non-default@example.cn');
  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();
  const signerDigest = await page.locator('#za-digest').innerText();

  await expect(page.locator('#identity-verdict')).toHaveAttribute('data-state', 'pass');
  await page.getByLabel(/Use RFC default/).check();
  await expect(page.locator('#identity-verdict')).toHaveAttribute('data-state', 'fail');
  await expect(page.locator('#identity-verdict')).toContainText('different Z_A');
  await expect(page.locator('#identity-failure-log')).toContainText('different Z_A');

  await page.getByLabel(/Use the signer's current ID/).check();
  await expect(page.locator('#identity-verdict')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#identity-failure-log')).toBeVisible();
  await page.getByLabel(/Use RFC default/).check();

  await page.getByLabel('Signer identity').fill('1234567812345678');
  await expect(page.locator('#signature-output')).toBeHidden();
  await expect(page.locator('#signature-retired')).toContainText('retired');
  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();
  const defaultDigest = await page.locator('#za-digest').innerText();
  expect(defaultDigest).not.toBe(signerDigest);
  await expect(page.locator('#identity-verdict')).toHaveAttribute('data-state', 'pass');
});

test('re-selecting the same values does not retire a fresh signature', async ({ page }) => {
  await unlockSignature(page);
  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();
  const id = await page.getByLabel('Signer identity').inputValue();
  await page.getByLabel('Signer identity').fill(id);

  await expect(page.locator('#signature-output')).toBeVisible();
  await expect(page.locator('#signature-retired')).toBeHidden();
  await expect(page.locator('#identity-verdict')).toHaveAttribute('data-state', 'pass');
});

test('both ciphertext layouts succeed, but a cross-order decoder names the mismatch', async ({ page }) => {
  await unlockCiphertext(page);
  await page.getByRole('button', { name: 'Encrypt once' }).click();

  await expect(page.locator('#roundtrip-c1c3c2')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#roundtrip-c1c2c3')).toHaveAttribute('data-state', 'pass');

  await page.getByLabel('Decoder expects').selectOption('C1C2C3');
  await expect(page.locator('#order-verdict')).toHaveAttribute('data-state', 'fail');
  await expect(page.locator('#order-verdict')).toContainText('ORDER MISMATCH');

  await page.getByLabel('Bytes sent on the wire').selectOption('C1C2C3');
  await expect(page.locator('#order-verdict')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#order-negative-claim')).toBeVisible();
  await expect(page.locator('#order-negative-claim')).toContainText(
    'interoperability failure, not a weakness',
  );
});

test('nonce-reuse fixture has two accepted signatures and an exposed key', async ({ page }) => {
  await unlockCiphertext(page);
  await page.getByRole('button', { name: 'Reuse k, sign twice, recover d' }).click();

  await expect(page.locator('#attack-verify-one')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#attack-verify-two')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#recovery-verdict')).toHaveAttribute('data-state', 'alarm');
  await expect(page.locator('#recovery-verdict')).toContainText('re-derives the victim public key byte-for-byte');
  await expect(page.locator('#nonce-negative-claim')).toBeVisible();
  await expect(page.locator('#nonce-negative-claim')).toContainText(
    /verification does not prove the nonce generator protected the private key/i,
  );
});

test('identical messages do not pretend to provide two recovery equations', async ({ page }) => {
  await unlockCiphertext(page);
  const firstMessage = await page.getByLabel('Message 1').inputValue();
  await page.getByLabel('Message 2').fill(firstMessage);
  await page.getByRole('button', { name: 'Reuse k, sign twice, recover d' }).click();

  await expect(page.locator('#attack-verify-one')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#attack-verify-two')).toHaveAttribute('data-state', 'pass');
  await expect(page.locator('#recovery-verdict')).toHaveAttribute('data-state', 'fail');
  await expect(page.locator('#recovery-verdict')).toContainText('Identical signatures');
});

test('hidden panes remain hidden and the page has one banner landmark', async ({ page }) => {
  await page.goto('.');
  await expect(page.getByRole('banner')).toHaveCount(1);
  await expect(page.locator('#pane-signature')).toBeHidden();
  await expect(page.locator('#pane-ciphertext')).toBeHidden();
});