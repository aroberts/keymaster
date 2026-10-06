// A phone stand-in that runs the real approval page in headless Chrome with a
// virtual WebAuthn authenticator. Tests/main.swift writes "approve <url>" or
// "deny <url>" lines to stdin; for each, this opens the page, clicks the
// button and prints one JSON line with what the page showed.
//
// One browser and one authenticator serve every line, so a passkey created
// on an enroll page signs on later approval pages.
//
// Uses only Node built-ins (fetch, WebSocket) and the DevTools protocol.
// KM_CHROME overrides the Chrome binary.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import readline from "node:readline";

const chromePath = process.env.KM_CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const profile = mkdtempSync(join(tmpdir(), "km-chrome-"));
const chrome = spawn(chromePath, [
  "--headless=new",
  "--remote-debugging-port=0",
  `--user-data-dir=${profile}`,
  "--no-first-run",
  "--no-default-browser-check",
  // The relay listens on 127.0.0.1 only; WebAuthn needs a hostname, not an IP.
  "--host-resolver-rules=MAP localhost 127.0.0.1",
  "about:blank",
], { stdio: "ignore" });

function cleanup() {
  chrome.kill();
  rmSync(profile, { recursive: true, force: true });
}
process.on("exit", cleanup);

let port = null;
for (let i = 0; i < 100 && !port; i++) {
  const file = join(profile, "DevToolsActivePort");
  if (existsSync(file)) port = readFileSync(file, "utf8").split("\n")[0];
  else await sleep(100);
}
if (!port) {
  console.error("Chrome did not start");
  process.exit(1);
}

const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
await new Promise((resolve) => ws.addEventListener("open", resolve));

let nextId = 1;
const pending = new Map();
const listeners = [];
ws.addEventListener("message", (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
  } else if (msg.method) {
    for (const listener of listeners) listener(msg);
  }
});

function send(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

async function evaluate(expression, userGesture = false) {
  const { result } = await send("Runtime.evaluate", { expression, userGesture, returnByValue: true, awaitPromise: true });
  return result.value;
}

async function waitFor(expression, timeout = 10000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return true;
    await sleep(100);
  }
  return false;
}

await send("Page.enable");
await send("Runtime.enable");
await send("WebAuthn.enable", { enableUI: false });
await send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

const pageState = `JSON.stringify({
  title: document.getElementById("title").textContent,
  status: document.getElementById("status").textContent,
  fields: Object.fromEntries(Array.from(document.querySelectorAll("dt"), (dt) => [dt.textContent, dt.nextElementSibling.textContent])),
})`;

const rl = readline.createInterface({ input: process.stdin });
for await (const line of rl) {
  const [action, url] = line.trim().split(" ");
  if (!url) continue;
  const loaded = new Promise((resolve) => listeners.push((msg) => msg.method === "Page.loadEventFired" && resolve()));
  await send("Page.navigate", { url });
  await loaded;
  listeners.length = 0;
  if (!(await waitFor(`!document.getElementById("actions").hidden`))) {
    console.log(JSON.stringify({ error: "actions never shown", page: JSON.parse(await evaluate(pageState)) }));
    continue;
  }
  const button = action === "deny" ? "deny" : "approve";
  await evaluate(`document.getElementById("${button}").click()`, true);
  await waitFor(`document.getElementById("status").textContent !== ""`);
  console.log(await evaluate(pageState));
}
process.exit(0);
