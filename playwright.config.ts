import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  timeout: 90_000,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4607/crypto-lab-sm2-forge/',
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'a11y',
      testMatch: /a11y\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'claims',
      testMatch: /claims\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npm run build && npm run preview -- --port 4607 --strictPort',
    url: 'http://localhost:4607/crypto-lab-sm2-forge/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});