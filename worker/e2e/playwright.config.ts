import { defineConfig } from "@playwright/test";

const AUTH_BASE = process.env.AUTH_BASE_URL ?? "https://authn.etzhayyim.com";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: AUTH_BASE,
    headless: true,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
