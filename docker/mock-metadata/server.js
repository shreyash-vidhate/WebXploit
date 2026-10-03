const http = require("http");

http.createServer((request, response) => {
  if (request.url !== "/latest/meta-data") {
    response.writeHead(404, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "Not found" }));
    return;
  }

  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify({
    token: "[FAKE_TOKEN_REDACTED]",
    environment: "local-lab-only"
  }));
}).listen(8081, "0.0.0.0");
