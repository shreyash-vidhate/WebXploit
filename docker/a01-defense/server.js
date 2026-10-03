const http = require("http");

const PORT = 3004;

const adminData = {
  users: [
    {
      id: 1,
      username: "admin",
      role: "administrator"
    },
    {
      id: 2,
      username: "security-test",
      role: "analyst"
    }
  ]
};

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/admin/users") {
    const authorization = req.headers.authorization;

    if (authorization !== "Bearer WEBXPLOIT-A01-LAB-ONLY") {
      res.writeHead(403, {
        "Content-Type": "application/json",
        "X-WebXploit-Lab": "A01-DEFENSE"
      });

      res.end(JSON.stringify({
        error: "Forbidden",
        message: "Administrative resource requires authorization."
      }));

      return;
    }

    res.writeHead(200, {
      "Content-Type": "application/json",
      "X-WebXploit-Lab": "A01-DEFENSE"
    });

    res.end(JSON.stringify(adminData));
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
  console.log(`WebXploit A01 defense listening on port ${PORT}`);
});
