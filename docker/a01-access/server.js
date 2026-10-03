const http = require("http");

const PORT = 3003;

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
  ],
  note: "Intentional WebXploit A01 lab data - local lab only."
};

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/admin/users") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "X-WebXploit-Lab": "A01"
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
  console.log(`WebXploit A01 lab listening on port ${PORT}`);
});
