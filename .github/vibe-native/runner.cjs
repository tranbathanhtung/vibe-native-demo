#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { execFile, spawn } = require("node:child_process");

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
  const streaming = String(req.url || "").includes("stream.mjpeg");
  const headers = { ...req.headers, "x-forwarded-proto": "https", "x-forwarded-host": req.headers.host || "" };
  if (streaming) headers["accept-encoding"] = "identity";
  const upstream = http.request(
    {
      host: "127.0.0.1",
      port,
      method: req.method,
      path: req.url,
      headers,
    },
    (up) => {
      const out = { ...up.headers };
      if (streaming) {
        delete out["content-length"];
        delete out["content-encoding"];
        out["cache-control"] = "no-cache, no-store, no-transform";
        out["x-accel-buffering"] = "no";
      }
      res.writeHead(up.statusCode || 502, out);
      res.socket?.setNoDelay(true);
      up.socket?.setNoDelay(true);
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

function motionCommand(message, size) {
  const x = Math.round(Number(message.x) * size.width);
  const y = Math.round(Number(message.y) * size.height);
  const phase = message.type === "begin" ? "DOWN" : message.type === "move" ? "MOVE" : message.type === "end" ? "UP" : null;
  if (!phase) return null;
  return ["shell", "input", "motionevent", phase, String(x), String(y)];
}

/** Android `screencap` without `-p`: 12 or 16 byte header, then tightly packed RGBA. */
function parseRawScreen(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 16) return null;
  const width = buffer.readUInt32LE(0);
  const height = buffer.readUInt32LE(4);
  const format = buffer.readUInt32LE(8);
  if (format !== 1 || width < 16 || height < 16 || width > 8192 || height > 8192) return null;
  const pixels = width * height * 4;
  const offset = buffer.length === 12 + pixels ? 12 : buffer.length === 16 + pixels ? 16 : 0;
  if (!offset) return null;
  return { width, height, pixels: buffer.subarray(offset, offset + pixels) };
}

function touchCommand(state, message, size) {
  const x = Math.round(Number(message.x) * size.width);
  const y = Math.round(Number(message.y) * size.height);
  if (message.type === "begin") return { state: { x, y, endX: x, endY: y, moved: false }, command: null };
  if (!state) return { state: null, command: null };
  if (message.type === "move") {
    const moved = state.moved || Math.hypot(x - state.x, y - state.y) > 8;
    return { state: { ...state, moved, endX: x, endY: y }, command: null };
  }
  if (message.type !== "end") return { state, command: null };
  const command = state.moved
    ? ["shell", "input", "swipe", String(state.x), String(state.y), String(state.endX ?? x), String(state.endY ?? y), "180"]
    : ["shell", "input", "tap", String(x), String(y)];
  return { state: null, command };
}

function buttonCommand(message) {
  if (message.phase === "up") return null;
  const keys = { home: "3", back: "4", lock: "26", power: "26", volumeup: "24", volumedown: "25", appswitcher: "187" };
  const key = keys[String(message.button || "").toLowerCase()];
  return key ? ["shell", "input", "keyevent", key] : null;
}

function scrollCommand(message, size) {
  const x = Math.round(Number(message.x) * size.width);
  const y = Math.round(Number(message.y) * size.height);
  const dx = Math.round(Number(message.dx) * size.width);
  const dy = Math.round(Number(message.dy) * size.height);
  if (!dx && !dy) return null;
  return ["shell", "input", "swipe", String(x), String(y), String(x - dx), String(y - dy), "120"];
}

function sendWs(socket, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  let header;
  if (body.length < 126) header = Buffer.from([0x82, body.length]);
  else {
    header = Buffer.alloc(4);
    header[0] = 0x82;
    header[1] = 126;
    header.writeUInt16BE(body.length, 2);
  }
  socket.write(header);
  socket.write(body);
}

/** One adb process at a time. Extra finger-moves collapse into the latest point so the queue cannot grow. */
function createInputPump() {
  let running = false;
  const queued = [];
  function drain() {
    if (running || queued.length === 0) return;
    const argv = queued.shift();
    running = true;
    execFile("adb", argv, () => {
      running = false;
      drain();
    });
  }
  return {
    run(argv) {
      if (argv[3] === "MOVE") {
        const index = queued.findIndex((item) => item[3] === "MOVE");
        if (index >= 0) queued[index] = argv;
        else queued.push(argv);
      } else queued.push(argv);
      drain();
    },
  };
}

function jpegFromRaw(parsed) {
  return new Promise((resolve) => {
    const ff = spawn(
      "ffmpeg",
      [
        "-hide_banner",
        "-loglevel",
        "error",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgba",
        "-s",
        `${parsed.width}x${parsed.height}`,
        "-i",
        "pipe:0",
        "-vf",
        "scale=720:-2",
        "-frames:v",
        "1",
        "-q:v",
        "6",
        "-f",
        "image2",
        "-vcodec",
        "mjpeg",
        "pipe:1",
      ],
      { stdio: ["pipe", "pipe", "ignore"] },
    );
    const chunks = [];
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const timer = setTimeout(() => {
      ff.kill("SIGKILL");
      finish(null);
    }, 2000);
    ff.stdout.on("data", (chunk) => chunks.push(chunk));
    ff.on("error", () => {
      clearTimeout(timer);
      finish(null);
    });
    ff.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return finish(null);
      const jpeg = Buffer.concat(chunks);
      if (jpeg.length < 4 || jpeg[0] !== 0xff || jpeg[1] !== 0xd8) return finish(null);
      finish(jpeg);
    });
    ff.stdin.on("error", () => undefined);
    ff.stdin.end(parsed.pixels);
  });
}

function acceptWebSocket(req, socket, ctx) {
  const key = req.headers["sec-websocket-key"];
  if (!key) {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return;
  }
  socket.setNoDelay(true);
  const accept = crypto.createHash("sha1").update(String(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  let buffer = Buffer.alloc(0);
  let gesture = null;
  const size = { width: 1080, height: 2400 };
  execFile("adb", ["shell", "wm", "size"], { encoding: "utf8" }, (_err, stdout) => {
    const match = String(stdout || "").match(/(\d+)x(\d+)/);
    if (match) {
      size.width = Number(match[1]);
      size.height = Number(match[2]);
    }
    sendWs(socket, Buffer.concat([Buffer.from([0x82]), Buffer.from(JSON.stringify({ width: size.width, height: size.height, orientation: "portrait" }))]));
  });
  socket.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 2) {
      const opcode = buffer[0] & 0x0f;
      const length = buffer[1] & 0x7f;
      const masked = (buffer[1] & 0x80) !== 0;
      let header = 2;
      if (length === 126) header = 4;
      else if (length === 127) header = 10;
      if (buffer.length < header) return;
      const payloadLength = length === 126 ? buffer.readUInt16BE(2) : length === 127 ? Number(buffer.readBigUInt64BE(2)) : length;
      const frameLength = header + (masked ? 4 : 0) + payloadLength;
      if (buffer.length < frameLength) return;
      const payload = Buffer.from(buffer.subarray(frameLength - payloadLength, frameLength));
      if (masked) {
        const mask = buffer.subarray(header, header + 4);
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      }
      buffer = buffer.subarray(frameLength);
      if (opcode === 0x8) {
        socket.end();
        return;
      }
      if (opcode === 0x9) {
        socket.write(Buffer.concat([Buffer.from([0x8a, payload.length]), payload]));
        continue;
      }
      if (opcode !== 0x2 && opcode !== 0x1) continue;
      if (payload.length < 2) continue;
      let message;
      try {
        message = JSON.parse(payload.subarray(1).toString("utf8"));
      } catch {
        continue;
      }
      if (payload[0] === 0x03) {
        if (ctx.motion) {
          const command = motionCommand(message, size);
          if (command) ctx.input.run(command);
        } else {
          const next = touchCommand(gesture, message, size);
          gesture = next.state;
          if (next.command) ctx.input.run(next.command);
        }
      } else if (payload[0] === 0x04) {
        const command = buttonCommand(message);
        if (command) ctx.input.run(command);
      } else if (payload[0] === 0x0b) {
        const command = scrollCommand(message, size);
        if (command) ctx.input.run(command);
      }
    }
  });
}

function androidServe(port) {
  const ctx = { motion: false, mode: "png", input: createInputPump() };
  const viewers = new Set();
  let capturing = false;
  execFile("ffmpeg", ["-version"], (err) => {
    ctx.mode = err ? "png" : "jpeg";
    console.log(`android frames: ${ctx.mode}`);
  });
  execFile("adb", ["shell", "input", "motionevent", "CANCEL", "0", "0"], { encoding: "utf8" }, (err, stdout, stderr) => {
    const text = `${stdout || ""}\n${stderr || ""}`;
    ctx.motion = !err && !/unknown command/i.test(text);
    console.log(ctx.motion ? "android touch: motionevent" : "android touch: tap/swipe");
  });

  function pngFrame() {
    return new Promise((resolve) => {
      execFile("adb", ["exec-out", "screencap", "-p"], { encoding: "buffer", maxBuffer: 12 * 1024 * 1024 }, (err, stdout) => {
        const frame = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout || []);
        if (err || frame.length < 8 || frame[0] !== 0x89) return resolve(null);
        resolve({ body: frame, type: "image/png" });
      });
    });
  }

  function captureFrame() {
    if (ctx.mode !== "jpeg") return pngFrame();
    return new Promise((resolve) => {
      execFile("adb", ["exec-out", "screencap"], { encoding: "buffer", maxBuffer: 24 * 1024 * 1024 }, async (err, stdout) => {
        const raw = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout || []);
        const parsed = !err && parseRawScreen(raw);
        const jpeg = parsed ? await jpegFromRaw(parsed) : null;
        if (!jpeg) {
          ctx.mode = "png";
          console.log("android frames: png (raw screencap unusable)");
          resolve(await pngFrame());
          return;
        }
        resolve({ body: jpeg, type: "image/jpeg" });
      });
    });
  }

  async function pumpFrames() {
    if (capturing) return;
    capturing = true;
    while (viewers.size > 0) {
      const frame = await captureFrame();
      if (!frame) {
        await new Promise((resolve) => setTimeout(resolve, 40));
        continue;
      }
      const head = Buffer.from(`--frame\r\nContent-Type: ${frame.type}\r\nContent-Length: ${frame.body.length}\r\n\r\n`);
      for (const res of viewers) {
        if (res.writableEnded) {
          viewers.delete(res);
          continue;
        }
        res.write(head);
        res.write(frame.body);
        res.write("\r\n");
      }
    }
    capturing = false;
  }

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
    const raw = new URL(req.url || "/", "http://localhost").searchParams.get("raw") === "1";
    res.writeHead(200, {
      "content-type": raw ? "application/octet-stream" : "multipart/x-mixed-replace; boundary=frame",
      "cache-control": "no-cache, no-store, no-transform",
      "x-accel-buffering": "no",
      connection: "close",
    });
    res.socket?.setNoDelay(true);
    viewers.add(res);
    res.on("close", () => viewers.delete(res));
    pumpFrames();
  });
  server.on("upgrade", (req, socket) => {
    const path = new URL(req.url || "/", "http://localhost").pathname;
    if (path !== "/ws") {
      socket.end("HTTP/1.1 404 Not Found\r\n\r\n");
      return;
    }
    acceptWebSocket(req, socket, ctx);
  });
  server.listen(Number(port), "127.0.0.1", () => console.log(`android stream on ${port}`));
}

if (require.main === module) {
  const [command] = process.argv.slice(2);
  const opts = flags(process.argv.slice(3));
  if (command === "gate") startGate(opts);
  else if (command === "publish-status") publishStatus(opts);
  else if (command === "android-serve") androidServe(opts.port || 3300);
  else {
    console.error("usage: runner.cjs gate|publish-status|android-serve");
    process.exit(1);
  }
}

module.exports = { touchCommand, motionCommand, parseRawScreen, buttonCommand, scrollCommand };
