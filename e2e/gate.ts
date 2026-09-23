import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';

export const NARROW = { width: 380, height: 800 };
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.push(`console.error: ${message.text()}`);
    }
  });
  return errors;
}

async function settle(page: Page): Promise<void> {
  await page.waitForFunction(() => document.getAnimations().every((animation) => animation.playState !== 'running'));
}

async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  expect(dimensions.scrollWidth, `horizontal overflow in state: ${label}`).toBeLessThanOrEqual(
    dimensions.clientWidth,
  );
}

async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const focusable = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((element) => element.scrollWidth > element.clientWidth + 1 || element.scrollHeight > element.clientHeight + 1)
      .filter((element) => {
        const style = getComputedStyle(element);
        return ['auto', 'scroll'].includes(style.overflowX) || ['auto', 'scroll'].includes(style.overflowY);
      })
      .filter((element) => element.tabIndex < 0 && !element.querySelector(focusable))
      .map((element) => `${element.tagName.toLowerCase()}.${element.className}`);
  });
  expect(unreachable, `scrolling regions without a keyboard route in state: ${label}`).toEqual([]);
}

async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const selector = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>(selector))
      .filter((element) => element.tabIndex >= 0 && element.checkVisibility({ checkVisibilityCSS: true }))
      .filter((element) => {
        const rect = element.getBoundingClientRect();
        let opacity = 1;
        for (let node: Element | null = element; node; node = node.parentElement) {
          opacity *= Number.parseFloat(getComputedStyle(node).opacity);
        }
        return opacity === 0 || rect.width === 0 || rect.height === 0;
      })
      .map((element) => `${element.tagName.toLowerCase()}#${element.id}.${element.className}`);
  });
  expect(invisible, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

async function expectOneBanner(page: Page): Promise<void> {
  await expect(page.getByRole('banner')).toHaveCount(1);
}

async function scan(page: Page, label: string): Promise<void> {
  await settle(page);

  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();

  const violations = [...wcag.violations, ...landmarks.violations].map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    nodes: violation.nodes.map((node) => node.target.join(' ')),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const incomplete = [...wcag.incomplete, ...landmarks.incomplete]
    .filter((result) => result.id !== 'color-contrast')
    .map((result) => ({ id: result.id, nodes: result.nodes.map((node) => node.target.join(' ')) }));
  expect(incomplete, `unresolved axe results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured text contrast failures in state: ${label}`).toEqual([]);

  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true),
      ),
    ),
  );
  expect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`).toEqual([]);

  expect(
    formatNonTextFailures(await auditNonText(page)),
    `non-text contrast failures in state: ${label}`,
  ).toEqual([]);
  await expectScrollersReachable(page, label);
  await expectNoInvisibleFocusTargets(page, label);
  await expectNoHorizontalOverflow(page, label);
}

export async function boot(page: Page): Promise<void> {
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');

  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must be active',
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expectOneBanner(page);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);
  await expect(page.locator('[data-theme-toggle], #theme-toggle, #themeToggle')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /The Signature/ })).toBeDisabled();
  await expect(page.getByRole('button', { name: /Ciphertext \+ Break/ })).toBeDisabled();
}

export async function driveAllStates(page: Page, viewportLabel: string): Promise<void> {
  const scanAt = (state: string) => scan(page, `${viewportLabel} / ${state}`);

  await scanAt('arrival with gated panes');

  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  await page.getByRole('button', { name: 'Run published vectors' }).click();
  await expect(page.locator('#signature-kat')).toContainText('PASS');
  await expect(page.locator('#encryption-kat')).toContainText('PASS');
  await scanAt('Annex A and Annex C pass');

  await page.getByRole('button', { name: 'Continue to the identity digest' }).click();
  await expect(page.locator('#pane-signature')).toBeVisible();
  await scanAt('signature pane before signing');

  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();
  await expect(page.locator('#identity-flow > li')).toHaveCount(8);
  await expect(page.locator('#identity-verdict')).toContainText('PASS');
  await scanAt('Z_A assembled and same identity accepted');

  await page.getByLabel(/Use RFC default/).check();
  await expect(page.locator('#identity-verdict')).toContainText('FAIL');
  await scanAt('default verifier identity rejected');

  await page.getByLabel('Signer identity').fill('merchant@example.cn');
  await expect(page.locator('#signature-output')).toBeVisible();
  await scanAt('same-value input is a no-op and keeps the verdict');

  await page.getByLabel('Signer identity').fill('different@example.cn');
  await expect(page.locator('#signature-output')).toBeHidden();
  await expect(page.locator('#signature-retired')).toContainText('retired');
  await scanAt('changed identity retires stale signature');

  await page.getByRole('button', { name: 'Build Z_A and sign' }).click();
  await page.getByLabel(/Use the signer's current ID/).check();
  await expect(page.locator('#identity-verdict')).toContainText('PASS');
  await page.locator('.equation-details > summary').click();
  await expect(page.locator('.equation-details')).toHaveAttribute('open', '');
  await scanAt('signature equation disclosure open');

  await page.getByRole('button', { name: 'Continue to ciphertext and nonce reuse' }).click();
  await expect(page.locator('#pane-ciphertext')).toBeVisible();
  await scanAt('ciphertext pane before encryption');

  await page.getByRole('button', { name: 'Encrypt once' }).click();
  await expect(page.locator('#roundtrip-c1c3c2')).toContainText('PASS');
  await expect(page.locator('#roundtrip-c1c2c3')).toContainText('PASS');
  await scanAt('both matching decoder orders round-trip');

  await page.getByLabel('Decoder expects').selectOption('C1C2C3');
  await expect(page.locator('#order-verdict')).toContainText('ORDER MISMATCH');
  await expect(page.locator('#order-failure-log')).toBeVisible();
  await scanAt('wrong-order decoder fails and names mismatch');

  await page.getByLabel('Bytes sent on the wire').selectOption('C1C2C3');
  await expect(page.locator('#order-verdict')).toContainText('PASS');
  await scanAt('older layout succeeds with matching decoder');

  await page.getByLabel('Plaintext').fill('encryption standard');
  await expect(page.locator('#order-output')).toBeVisible();
  await page.getByLabel('Plaintext').fill('changed plaintext');
  await expect(page.locator('#order-output')).toBeHidden();
  await expect(page.locator('#encryption-retired')).toContainText('retired');
  await scanAt('changed plaintext retires stale ciphertext');

  await page.getByLabel('Message 2').fill('Approve invoice 1042');
  await page.getByRole('button', { name: 'Reuse k, sign twice, recover d' }).click();
  await expect(page.locator('#recovery-verdict')).toContainText('Identical signatures');
  await scanAt('identical messages refuse bogus recovery');

  await page.getByLabel('Message 2').fill('Approve invoice 9001');
  await page.getByRole('button', { name: 'Reuse k, sign twice, recover d' }).click();
  await expect(page.locator('#attack-verify-one')).toContainText('PASS');
  await expect(page.locator('#attack-verify-two')).toContainText('PASS');
  await expect(page.locator('#recovery-verdict')).toContainText('ALARM');
  await scanAt('two accepted signatures expose the exact private key');

  await page.getByRole('button', { name: 'Reuse k, sign twice, recover d' }).hover();
  await scanAt('danger control hover state');
  await page.getByRole('link', { name: 'View this project on GitHub' }).hover();
  await scanAt('top-bar link hover state');
}