#!/usr/bin/env node
"use strict";

const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { execFile } = require("node:child_process");

const COOKIE = "vibe_native_k";
const AGENT_PREFIX = "/agent-device";
const DENIED = `<!doctype html><meta charset=utf-8><title>vibe-native</title>
<body style="font:14px/1.6 system-ui;margin:12vh auto;max-width:34rem;padding:0 1.5rem">
<h1>vibe-native</h1>
<p>This device stream needs the access key from the link the CLI printed.</p>
</body>`;

function flags(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) out[key] = "true";
    else {
      out[key] = next;
      i++;
    }
  }
  return out;
}

function timingSafeEqual(a, b) {
  if (!a || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function cookieToken(req) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === COOKIE) return rest.join("=");
  }
  return null;
}

function bearerToken(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || "").trim());
  return match ? match[1] : null;
}

function authorize(req, token) {
  if (timingSafeEqual(cookieToken(req), token)) return "cookie";
  if (timingSafeEqual(bearerToken(req), token)) return "bearer";
  const url = new URL(req.url || "/", "http://localhost");
  if (timingSafeEqual(url.searchParams.get("k"), token)) return "query";
  return false;
}

function gateToken() {
  if (process.env.GATE_TOKEN) return process.env.GATE_TOKEN;
  if (process.env.VIBE_GATE_TOKEN) return process.env.VIBE_GATE_TOKEN;
  const session = process.env.SESSION;
  if (session && process.env.VIBE_SESSION_KEYS) {
    const book = JSON.parse(process.env.VIBE_SESSION_KEYS);
    if (book[session]?.token) return book[session].token;
  }
  throw new Error("Refusing to proxy an unauthenticated simulator: no gate token");
}

function proxyHttp(req, res, port) {
  const upstream = http.request(
    {
      host: "127.0.0.1",
      port,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, "x-forwarded-proto": "https", "x-forwarded-host": req.headers.host || "" },
    },
    (up) => {
      res.writeHead(up.statusCode || 502, up.headers);
      up.pipe(res);
    },
  );
  upstream.on("error", (err) => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
    res.end(`upstream error: ${err.message}`);
  });
  req.pipe(upstream);
}

function startGate(opts) {
  const token = gateToken();
  const agentPort = Number(opts.agent || 0);
  const targetPort = Number(opts.target);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url || "/", "http://localhost");
    if (url.pathname === "/__vibe/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, target: targetPort, agent: agentPort || null }));
      return;
    }
    if (url.pathname === "/__vibe/devices") {
      if (!authorize(req, token)) {
        res.writeHead(403);
        res.end(DENIED);
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(process.env.VIBE_DEVICES_JSON || "[]");
      return;
    }
    const auth = authorize(req, token);
    if (!auth) {
      res.writeHead(403, { "content-type": "text/html; charset=utf-8" });
      res.end(DENIED);
      return;
    }
    const path = url.pathname;
    const agent = agentPort && (path === AGENT_PREFIX || path.startsWith(`${AGENT_PREFIX}/`));
    if (auth === "query" && !agent) {
      url.searchParams.delete("k");
      res.writeHead(302, {
        "set-cookie": `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`,
        location: url.pathname + url.search,
      });
      res.end();
      return;
    }
    proxyHttp(req, res, agent ? agentPort : targetPort);
  });
  server.on("upgrade", (req, socket, head) => {
    if (!authorize(req, token)) {
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    const path = new URL(req.url || "/", "http://localhost").pathname;
    const port = agentPort && (path === AGENT_PREFIX || path.startsWith(`${AGENT_PREFIX}/`)) ? agentPort : targetPort;
    const upstream = net.connect(port, "127.0.0.1", () => {
      const headers = Object.entries({ ...req.headers, "x-forwarded-proto": "https", "x-forwarded-host": req.headers.host })
        .filter((entry) => entry[1] !== undefined)
        .map(([key, value]) => (Array.isArray(value) ? value.map((item) => `${key}: ${item}`).join("\r\n") : `${key}: ${value}`))
        .join("\r\n");
      upstream.write(`${req.method} ${req.url} HTTP/1.1\r\n${headers}\r\n\r\n`);
      if (head.length) upstream.write(head);
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    const drop = () => {
      socket.destroy();
      upstream.destroy();
    };
    upstream.on("error", drop);
    socket.on("error", drop);
  });
  server.listen(Number(opts.listen || 3199), "127.0.0.1", () => {
    const address = server.address();
    console.log(`gate listening on ${typeof address === "object" && address ? address.port : opts.listen}`);
  });
}

function publishStatus(opts) {
  const body = JSON.stringify({
    state: opts.state || "success",
    context: opts.context,
    description: String(opts.description || "").slice(0, 140),
    ...(opts.url ? { target_url: opts.url } : {}),
  });
  const req = https.request(
    {
      hostname: "api.github.com",
      path: `/repos/${opts.repo}/statuses/${opts.sha}`,
      method: "POST",
      headers: {
        authorization: `Bearer ${process.env.GH_TOKEN || ""}`,
        accept: "application/vnd.github+json",
        "user-agent": "vibe-native",
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
      },
    },
    (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        if ((res.statusCode || 500) >= 300) {
          console.error(`status publish failed (${res.statusCode}): ${Buffer.concat(chunks).toString("utf8").slice(0, 300)}`);
          process.exit(1);
        }
      });
    },
  );
  req.on("error", (err) => {
    console.error(err.message);
    process.exit(1);
  });
  req.end(body);
}

function androidServe(port) {
  const server = http.createServer((req, res) => {
    const path = new URL(req.url || "/", "http://localhost").pathname;
    if (path === "/health" || path === "/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
      return;
    }
    if (path !== "/stream.mjpeg") {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, {
      "content-type": "multipart/x-mixed-replace; boundary=frame",
      "cache-control": "no-cache, no-store",
      connection: "close",
    });
    let inflight = false;
    const timer = setInterval(() => {
      if (inflight || res.writableEnded) return;
      inflight = true;
      execFile("adb", ["exec-out", "screencap", "-p"], { encoding: "buffer", maxBuffer: 12 * 1024 * 1024 }, (err, stdout) => {
        inflight = false;
        if (err || res.writableEnded) return;
        const frame = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
        if (frame.length < 8) return;
        res.write(`--frame\r\nContent-Type: image/png\r\nContent-Length: ${frame.length}\r\n\r\n`);
        res.write(frame);
        res.write("\r\n");
      });
    }, 200);
    res.on("close", () => clearInterval(timer));
  });
  server.listen(Number(port), "127.0.0.1", () => console.log(`android stream on ${port}`));
}

const [command] = process.argv.slice(2);
const opts = flags(process.argv.slice(3));
if (command === "gate") startGate(opts);
else if (command === "publish-status") publishStatus(opts);
else if (command === "android-serve") androidServe(opts.port || 3300);
else {
  console.error("usage: runner.cjs gate|publish-status|android-serve");
  process.exit(1);
}
