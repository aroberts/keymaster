"use strict";

// The approval and enrollment page. It shows the request keymaster sent, then
// asks the passkey to sign SHA-256 of the exact request bytes. Everything
// rendered here goes through textContent; the request is attacker-influenced
// text (key names, the caller's reason) and must never reach innerHTML.

const id = location.pathname.split("/").pop();
const api = `/api/requests/${encodeURIComponent(id)}`;
const $ = (name) => document.getElementById(name);

let request = null;
let challenge = null;
let timer = null;

function b64urlDecode(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

function b64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let raw = "";
  for (const b of bytes) raw += String.fromCharCode(b);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hex(buffer, count) {
  return Array.from(new Uint8Array(buffer).slice(0, count), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Groups of four hex digits, matching what keymaster prints in the terminal.
function code(buffer, count) {
  return hex(buffer, count).match(/.{1,4}/g).join("-");
}

function setStatus(text, kind) {
  const el = $("status");
  el.textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
}

function addField(label, value, className) {
  if (value === undefined || value === null || value === "") return;
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = String(value);
  if (className) dd.className = className;
  $("fields").append(dt, dd);
}

const verbs = { get: "Read", set: "Store", delete: "Delete" };

function formatDuration(seconds) {
  if (seconds < 120) return `${seconds} seconds`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} minutes`;
  return `${Math.round(seconds / 3600)} hours`;
}

function renderApprove(r) {
  if (r.action === "test") {
    $("title").textContent = "Test approval";
    $("summary").textContent = `from ${r.user}@${r.host}. Approving releases nothing.`;
    addField("Requested by", r.caller, "mono");
    addField("Request code", code(challenge, 4), "mono");
    $("approve").textContent = "Approve with Face ID";
    return;
  }
  const verb = verbs[r.action] || r.action;
  $("title").textContent = `${verb} “${r.key}”`;
  $("summary").textContent = `on ${r.user}@${r.host}`;
  addField("Key", r.key, "mono");
  addField("Session", r.session);
  if (r.scope) {
    addField("Also allows", `reading every key starting with “${r.scope}” for ${formatDuration(r.ttl)}`, "warn");
  } else if (r.action === "get" && r.ttl) {
    addField("Reuse", `this key, without asking again, for ${formatDuration(r.ttl)}`);
  }
  addField("Requested by", r.caller, "mono");
  addField("In directory", r.cwd, "mono");
  addField("Reason given by the caller", r.reason, "claim");
  addField("Requested at", new Date(r.iat * 1000).toLocaleString());
  addField("Request code", code(challenge, 4), "mono");
  $("approve").textContent = "Approve with Face ID";
}

function renderEnroll(r) {
  $("title").textContent = "Enroll a passkey";
  $("summary").textContent = `for keymaster on ${r.user}@${r.host}`;
  addField("Label", r.label);
  addField("Requested at", new Date(r.iat * 1000).toLocaleString());
  addField("Request code", code(challenge, 4), "mono");
  $("approve").textContent = "Create passkey";
}

function showFinal(status) {
  $("actions").hidden = true;
  clearInterval(timer);
  $("expiry").textContent = "";
  if (status === "responded") setStatus("Answered. keymaster is checking the signature.", "ok");
  else if (status === "denied") setStatus("Denied.", "error");
}

function tick() {
  const left = Math.round(request.exp - Date.now() / 1000);
  if (left <= 0) {
    $("actions").hidden = true;
    $("expiry").textContent = "";
    setStatus("This request has expired.", "error");
    clearInterval(timer);
    return;
  }
  $("expiry").textContent = `Expires in ${left}s`;
}

async function post(path, body) {
  const res = await fetch(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `relay answered ${res.status}`);
  }
}

function busy(on) {
  $("approve").disabled = on;
  $("deny").disabled = on;
}

// navigator.credentials must be called straight from the click, with nothing
// awaited first, or Safari drops the user activation. The challenge is
// computed at load for that reason.
async function approve() {
  busy(true);
  setStatus("");
  const timeout = Math.max(1000, request.exp * 1000 - Date.now());
  try {
    if (request.kind === "enroll") {
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { id: location.hostname, name: "keymaster" },
          user: {
            id: b64urlDecode(request.userId),
            name: `keymaster ${request.user}@${request.host}`,
            displayName: request.label || `keymaster on ${request.host}`,
          },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          attestation: "none",
          timeout,
        },
      });
      const r = credential.response;
      if (r.getPublicKeyAlgorithm() !== -7) throw new Error("the passkey is not ES256");
      const spki = r.getPublicKey();
      await post("/response", {
        type: "credential",
        credentialId: b64urlEncode(credential.rawId),
        publicKey: b64urlEncode(spki),
        publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
        authenticatorData: b64urlEncode(r.getAuthenticatorData()),
        clientDataJSON: b64urlEncode(r.clientDataJSON),
      });
      const fingerprint = await crypto.subtle.digest("SHA-256", spki);
      addField("Credential ID", b64urlEncode(credential.rawId), "mono");
      addField("Key fingerprint", code(fingerprint, 8), "mono");
      showFinal("responded");
      setStatus("Passkey created. Check that keymaster prints the same fingerprint.", "ok");
    } else {
      const credential = await navigator.credentials.get({
        publicKey: { challenge, rpId: location.hostname, userVerification: "required", timeout },
      });
      const r = credential.response;
      await post("/response", {
        type: "assertion",
        credentialId: b64urlEncode(credential.rawId),
        authenticatorData: b64urlEncode(r.authenticatorData),
        clientDataJSON: b64urlEncode(r.clientDataJSON),
        signature: b64urlEncode(r.signature),
      });
      showFinal("responded");
    }
  } catch (err) {
    busy(false);
    const message = err.name === "NotAllowedError" ? "Canceled or timed out. You can try again." : err.message;
    setStatus(message, "error");
  }
}

async function deny() {
  busy(true);
  try {
    await post("/deny");
    showFinal("denied");
  } catch (err) {
    busy(false);
    setStatus(err.message, "error");
  }
}

async function load() {
  let data;
  try {
    const res = await fetch(api);
    if (!res.ok) throw new Error("This request was not found. It may have expired.");
    data = await res.json();
  } catch (err) {
    $("title").textContent = "Request unavailable";
    setStatus(err.message, "error");
    return;
  }
  const bytes = b64urlDecode(data.request);
  request = JSON.parse(new TextDecoder().decode(bytes));
  challenge = await crypto.subtle.digest("SHA-256", bytes);
  if (request.kind === "enroll") renderEnroll(request);
  else renderApprove(request);
  if (data.status !== "pending") {
    showFinal(data.status);
    return;
  }
  if (!window.PublicKeyCredential) {
    setStatus("This browser does not support passkeys.", "error");
    return;
  }
  $("actions").hidden = false;
  $("approve").addEventListener("click", approve);
  $("deny").addEventListener("click", deny);
  tick();
  timer = setInterval(tick, 1000);
}

load();
