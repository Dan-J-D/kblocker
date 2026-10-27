// Runs the Tauri CLI so that stopping `pnpm tauri dev` with Ctrl+C exits
// cleanly. The terminal sends SIGINT to every process in the foreground group,
// so tauri shuts itself down; this just stops pnpm from reporting the
// interrupted exit as ELIFECYCLE. Other exits pass through unchanged.
import { spawn } from "node:child_process";

let interrupted = false;
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => (interrupted = true));
}

const child = spawn("tauri", process.argv.slice(2), { stdio: "inherit" });
child.on("error", (err) => {
  console.error(`Failed to start the Tauri CLI: ${err.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (interrupted || signal === "SIGINT" || code === 130) process.exit(0);
  process.exit(code ?? 1);
});
