// HTTPS in front of a plain-HTTP relay for local interop runs (production relays sit behind a
// TLS-terminating proxy too). Usage: node tls-proxy.mjs <listen port> <upstream port> <cert> <key>
import { readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const [listen, upstream, cert, key] = process.argv.slice(2);
https
  .createServer({ cert: readFileSync(cert), key: readFileSync(key) }, (req, res) => {
    const forward = http.request(
      { host: "127.0.0.1", port: upstream, method: req.method, path: req.url, headers: req.headers },
      (up) => {
        res.writeHead(up.statusCode, up.headers);
        up.pipe(res);
      },
    );
    forward.on("error", () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(forward);
  })
  .listen(Number(listen), "127.0.0.1", () => console.log(`tls proxy :${listen} -> :${upstream}`));
