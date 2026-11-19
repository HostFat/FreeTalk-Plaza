// Build the example-data UI, then serve the static bundle for Playwright.
//
// Starting a static server only after `dx build` finishes avoids the dev
// server's "app is being rebuilt" page: the tests never run against a stale
// wasm bundle. `dx` comes from PATH (Nix) or from DX_BIN (the local wrapper).
import { spawnSync } from "node:child_process";
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import path from "node:path";

const dx = process.env.DX_BIN || "dx";
const port = Number(process.env.PORT ?? 8082);
const host = process.env.HOST ?? "127.0.0.1";

// A clean checkout has no ui/node_modules and no generated styles.css.
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
if (
  !existsSync(path.resolve("node_modules")) ||
  !existsSync(path.resolve("assets", "styles.css"))
) {
  console.log("Installing UI dependencies and building Tailwind CSS...");
  let step = spawnSync(npm, ["install", "--no-audit", "--no-fund"], {
    stdio: "inherit",
  });
  if (step.status !== 0) {
    process.exit(step.status ?? 1);
  }
  step = spawnSync(npm, ["run", "build:css"], { stdio: "inherit" });
  if (step.status !== 0) {
    process.exit(step.status ?? 1);
  }
}

// chat_delegate.rs include_bytes!s the release delegate WASM from target/.
const delegateWasm = path.resolve(
  "..",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "plaza_delegate.wasm",
);
if (!existsSync(delegateWasm)) {
  console.log("Building the delegate WASM...");
  const step = spawnSync(
    "cargo",
    [
      "run",
      "--quiet",
      "--manifest-path",
      "tools/wasm-tool/Cargo.toml",
      "--",
      "sync",
    ],
    { cwd: path.resolve(".."), stdio: "inherit" },
  );
  if (step.status !== 0) {
    process.exit(step.status ?? 1);
  }
}

const build = spawnSync(
  dx,
  ["build", "--package", "plaza-ui", "--features", "example-data,no-sync"],
  { stdio: "inherit" },
);
if (build.error) {
  console.error(`Could not run ${dx}: ${build.error.message}`);
  process.exit(1);
}
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const candidates = [
  path.resolve("..", "target", "dx", "plaza-ui", "debug", "web", "public"),
  path.resolve("..", "target", "dx", "plaza-ui", "release", "web", "public"),
];
const root = candidates.find((candidate) =>
  existsSync(path.join(candidate, "index.html")),
);
if (!root) {
  console.error(
    "Could not find target/dx/plaza-ui/*/web/public/index.html after dx build.",
  );
  process.exit(1);
}

const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".wasm", "application/wasm"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".gif", "image/gif"],
  [".webp", "image/webp"],
  [".ico", "image/x-icon"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
  [".ttf", "font/ttf"],
  [".map", "application/json"],
]);

function resolvePath(url) {
  const pathname = decodeURIComponent(new URL(url, "http://localhost").pathname);
  const normalized = path.normalize(pathname).replace(/^(\.\.[/\\])+/, "");
  let file = path.join(root, normalized);
  // Keep the static server inside the bundle.
  if (!file.startsWith(root)) {
    file = path.join(root, "index.html");
  }
  if (existsSync(file) && statSync(file).isFile()) {
    return file;
  }
  // Hash routing only needs index.html, but direct routes get the SPA too.
  return path.join(root, "index.html");
}

const server = createServer((req, res) => {
  const file = resolvePath(req.url ?? "/");
  const type = types.get(path.extname(file).toLowerCase()) ?? "application/octet-stream";
  res.writeHead(200, {
    "Content-Type": type,
    "Cache-Control": "no-store",
  });
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  createReadStream(file).pipe(res);
});

server.listen(port, host, () => {
  console.log(`Serving ${root} on http://${host}:${port}/`);
});

function stop() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2_000).unref();
}
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
