// Experimental HTTPS CONNECT with user-supplied, provider-issued credentials.
import https from "node:https";
import http from "node:http";
import tls from "node:tls";
import net from "node:net";

export interface ManualHttpsConfig { hostname: string; port: number; username: string; password: string }

export function manualHttpsConfig(env: NodeJS.ProcessEnv): ManualHttpsConfig {
  const hostname = env.WINDLAB_PROXY_HOST?.trim() ?? "";
  const port = Number(env.WINDLAB_PROXY_PORT ?? "443");
  const username = env.WINDLAB_PROXY_USER ?? "", password = env.WINDLAB_PROXY_PASSWORD ?? "";
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(hostname) || net.isIP(hostname))
    throw new Error("Set WINDLAB_PROXY_HOST to the provider's TLS hostname (not a URL or IP).");
  if (![443, 9443].includes(port)) throw new Error("Proxy port must be 443 or 9443.");
  if (!username || !password || /[:\r\n\0]/.test(username) || /[\r\n\0]/.test(password))
    throw new Error("Set provider-issued proxy credentials in WINDLAB_PROXY_USER and WINDLAB_PROXY_PASSWORD.");
  return { hostname, port, username, password };
}

export function connectAuthority(host: string, port: number): string {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid target port.");
  if (net.isIP(host) === 6) return "[" + host + "]:" + port;
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(host)) throw new Error("Invalid target hostname.");
  return host + ":" + port;
}

/** No insecure TLS or direct fallback. Never report raw proxy headers or credentials. */
export async function dialManualHttps(config: ManualHttpsConfig, host: string, port: number, ms = 15000): Promise<tls.TLSSocket> {
  const authority = connectAuthority(host, port);
  const authorization = Buffer.from(config.username + ":" + config.password, "utf8").toString("base64");
  return new Promise((resolve, reject) => {
    let done = false;
    const fail = (reason: string) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      req.destroy();
      reject(new Error(reason));
    };
    const req = https.request({
      hostname: config.hostname, port: config.port, servername: config.hostname,
      method: "CONNECT", path: authority, agent: false, rejectUnauthorized: true,
      headers: { Host: authority, "Proxy-Authorization": "Basic " + authorization },
    });
    const timer = setTimeout(() => fail("HTTPS proxy connection timed out."), ms);
    req.once("error", (err: NodeJS.ErrnoException) => {
      const code = err.code;
      fail("HTTPS proxy transport failed" + (code && /^[A-Z0-9_]+$/.test(code) ? " (" + code + ")." : "."));
    });
    req.once("connect", (res, socket, head) => {
      if (done) return void socket.destroy();
      if (res.statusCode !== 200) {
        socket.destroy();
        return fail(res.statusCode === 407 ? "HTTPS proxy rejected proxy credentials (407)." :
          "HTTPS CONNECT rejected (status " + (res.statusCode ?? "unknown") + ").");
      }
      done = true;
      clearTimeout(timer);
      socket.pause();
      socket.on("error", () => {});
      if (head.length) socket.unshift(head);
      resolve(socket as tls.TLSSocket);
    });
    req.once("response", res => { res.destroy(); fail("HTTPS proxy did not establish a CONNECT tunnel."); });
    req.end();
  });
}

/** Verify the target's TLS certificate and a real IP response through the tunnel. */
export async function checkManualHttps(config: ManualHttpsConfig): Promise<string> {
  const host = "api.ipify.org";
  const tunnel = await dialManualHttps(config, host, 443);
  const secure = tls.connect({ socket: tunnel, servername: host, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => { secure.destroy(); reject(new Error("Target TLS timed out.")); }, 12000);
      secure.once("secureConnect", () => { clearTimeout(timer); resolve(); });
      secure.once("error", () => { clearTimeout(timer); reject(new Error("Target TLS verification or connection failed.")); });
      secure.once("close", () => { clearTimeout(timer); reject(new Error("Target TLS closed.")); });
    });
    return await new Promise<string>((resolve, reject) => {
      let body = "";
      const req = http.request({ host, path: "/", method: "GET", createConnection: () => secure,
        headers: { Host: host, Connection: "close" } }, res => {
        if (res.statusCode !== 200) { res.destroy(); return reject(new Error("IP check returned a non-200 response.")); }
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          body += chunk;
          if (body.length > 128) { res.destroy(); reject(new Error("Invalid IP response.")); }
        });
        res.once("error", () => reject(new Error("IP response failed.")));
        res.once("end", () => {
          const ip = body.trim();
          if (!net.isIP(ip)) reject(new Error("Invalid IP response."));
          else resolve(ip);
        });
      });
      const timer = setTimeout(() => { req.destroy(); reject(new Error("IP check timed out.")); }, 12000);
      req.once("close", () => clearTimeout(timer));
      req.once("error", () => { clearTimeout(timer); reject(new Error("IP check request failed.")); });
      req.end();
    });
  } finally { secure.destroy(); tunnel.destroy(); }
}
