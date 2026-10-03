const http = require("http");

const PORT = 3002;

const exposedFile = {
  filename: "application-config.bak",
  content: "WEBXPLOIT_DEMO_SECRET=[REDACTED_DEMO_VALUE]\nDB_PASSWORD=[REDACTED_DEMO_VALUE]\n",
  note: "Intentional A02 lab exposure - do not use outside the local WebXploit lab."
};

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/backup/application-config.bak") {
    res.writeHead(200, {
      "Content-Type": "text/plain",
      "X-WebXploit-Lab": "A02"
    });
    res.end(exposedFile.content);
    return;
  }

  res.writeHead(404, {
    "Content-Type": "application/json"
  });

  res.end(JSON.stringify({
    error: "Not Found"
  }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`WebXploit A02 lab listening on port ${PORT}`);
});
