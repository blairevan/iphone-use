/** Run the production relay in isolated Cloudflare-shaped fixtures, no network. */
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const { Phone, default: worker } = await import(process.env.RELAY_TEST_MODULE
  ? pathToFileURL(process.env.RELAY_TEST_MODULE).href : new URL("../relay/src/index.ts", import.meta.url).href);

globalThis.WebSocketRequestResponsePair = class {
  constructor(request, response) { this.request = request; this.response = response; }
};
const id = "abcdefghijklmnopqrstuv";
const url = `https://relay.example/p/${id}/agent/status`;
const frames = [];
let answer = true;
let phone;
const tunnel = {
  send(text) {
    const frame = JSON.parse(text);
    frames.push(frame);
    if (answer && frame.t === "req") queueMicrotask(async () => {
      await phone.webSocketMessage(tunnel, JSON.stringify({ t: "res", id: frame.id, s: 204, h: [] }));
      await phone.webSocketMessage(tunnel, JSON.stringify({ t: "end", id: frame.id }));
    });
  },
};
const state = {
  setWebSocketAutoResponse() {},
  getWebSockets() { return [tunnel]; },
  storage: { async get() { return undefined; }, async put() {} },
};
phone = new Phone(state, {});

assert.equal((await worker.fetch(new Request(url.replace("https:", "http:")), {})).status, 403);
assert.equal((await phone.fetch(new Request(url.replace("https:", "http:")))).status, 403);
assert.equal((await phone.fetch(new Request("https://relay.example/invalid"))).status, 404);
console.log("PASS: edge and durable-object routes both reject plaintext and malformed routes");

const response = await phone.fetch(new Request(url, { headers: {
  authorization: "Bearer synthetic-session",
  "x-iphone-use-relay-auth": "forged-internal-credential",
  "x-real-ip": "forged-source", "x-forwarded-proto": "http",
  "forwarded": "for=forged-source", "cf-connecting-ip": "192.0.2.7",
} }));
assert.equal(response.status, 204);
const request = frames.find(frame => frame.t === "req");
const headers = Object.fromEntries(request.h);
assert.equal(headers.authorization, "Bearer synthetic-session");
assert.equal(headers["x-iphone-use-relay-auth"], undefined);
assert.equal(headers["x-real-ip"], undefined);
assert.equal(headers.forwarded, undefined);
assert.equal(headers["x-forwarded-proto"], "https");
assert.equal(request.source, "192.0.2.7");
console.log("PASS: client forwarding/internal headers cannot appoint themselves trusted ingress");

let cancelled = false;
const oversized = new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array((1 << 20) + 1)); },
  cancel() { cancelled = true; },
});
assert.equal((await phone.fetch(new Request(url, { method: "POST", body: oversized, duplex: "half" }))).status, 413);
assert.equal(cancelled, true);
console.log("PASS: oversized streamed bodies are cancelled before full buffering");

const controllers = [];
const waiting = Array.from({ length: 32 }, () => {
  const body = new ReadableStream({ start(controller) { controllers.push(controller); } });
  return phone.fetch(new Request(url, { method: "POST", body, duplex: "half" }));
});
assert.equal((await phone.fetch(new Request(url))).status, 503);
for (const controller of controllers) controller.close();
assert.equal((await Promise.all(waiting)).every(item => item.status === 204), true);
console.log("PASS: admission includes requests whose streamed bodies have not finished");

answer = false;
const abort = new AbortController();
const pending = phone.fetch(new Request(url, { signal: abort.signal }));
await new Promise(resolve => setTimeout(resolve, 0));
abort.abort();
assert.equal((await pending).status, 499);
assert.equal(frames.at(-1).t, "cancel");
console.log("PASS: client cancellation resolves pending fetches and releases remote work");
