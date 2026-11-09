// Copies the backend fixture next to the app so the bundler can import it.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../../backend/tests/fixtures/sample_report.json");
const dst = resolve(here, "../lib/mock/sample_report.json");
mkdirSync(dirname(dst), { recursive: true });
copyFileSync(src, dst);
console.log("synced sample_report.json");
