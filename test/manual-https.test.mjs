import assert from "node:assert/strict";
import { manualHttpsConfig, connectAuthority, dialManualHttps } from "../dist/manual-https.js";
import net from "node:net";
const env = { WINDLAB_PROXY_HOST: "proxy.example.com", WINDLAB_PROXY_USER: "test", WINDLAB_PROXY_PASSWORD: "test:password" };
assert.equal(manualHttpsConfig(env).port, 443);
assert.equal(manualHttpsConfig({ ...env, WINDLAB_PROXY_PORT: "9443" }).port, 9443);
for (const bad of ["http://proxy.example.com", "127.0.0.1", "bad\r\nname", ""]) assert.throws(() => manualHttpsConfig({ ...env, WINDLAB_PROXY_HOST: bad }));
assert.throws(() => manualHttpsConfig({ ...env, WINDLAB_PROXY_PORT: "80" }));
assert.throws(() => manualHttpsConfig({ ...env, WINDLAB_PROXY_USER: "user:name" }));
assert.throws(() => manualHttpsConfig({ ...env, WINDLAB_PROXY_PASSWORD: "" }));
assert.equal(connectAuthority("2001:db8::1", 443), "[2001:db8::1]:443");
assert.equal(connectAuthority("example.com", 443), "example.com:443");
assert.throws(() => connectAuthority("a\r\nX: secret", 443));
assert.throws(() => connectAuthority("example.com", 65536));
const server = net.createServer(s => { s.once("data", b => { assert(!b.includes("Proxy-Authorization")); s.end("HTTP/1.1 200 OK\r\n\r\n"); }); });
await new Promise(r => server.listen(0, "127.0.0.1", r));
try {
  await assert.rejects(dialManualHttps({ ...manualHttpsConfig(env), hostname: "127.0.0.1", port: server.address().port }, "example.com", 443, 2000), /HTTPS proxy transport failed|timed out/);
} finally { await new Promise(r => server.close(r)); }
console.log("manual HTTPS configuration and TLS failure tests passed");
