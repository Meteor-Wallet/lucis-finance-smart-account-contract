// @ts-check
import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    timeout: 120_000,
    reporter: [['list']],
    use: {
        trace: 'on-first-retry',
    },
    workers: 1, // <---- forces all tests to run sequentially
    fullyParallel: false,
});
