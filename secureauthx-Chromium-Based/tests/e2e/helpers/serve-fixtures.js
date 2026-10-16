import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES_DIR = path.resolve(__dirname, "../fixtures");

/**
 * Serves tests/e2e/fixtures/ over plain HTTP on the given port.
 *
 * This matters, not just for convenience: SecureAuthX's manifest.json
 * content-script matches are for http and https origins only (see
 * manifest.json) -- file:// pages do not match, so the extension would
 * not inject at all against a bare file:// fixture. Every E2E test must
 * load fixtures through this server.
 */
export function serveFixtures(port) {
  const proc = spawn("python3", ["-m", "http.server", String(port)], {
    cwd: FIXTURES_DIR,
    stdio: "ignore",
  });
  return {
    url: (file) => `http://localhost:${port}/${file}`,
    close: () => proc.kill(),
  };
}

/** Small sleep helper for the few spots a fixed delay is genuinely simplest. */
export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
