const http = require("http");

const allowedTarget = "http://mock-metadata:8081/latest/meta-data";

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json"
  });
  response.end(JSON.stringify(body));
}

http.createServer((request, response) => {
  const requestUrl = new URL(request.url, "http://localhost");

  // A10 - SSRF simulation
  if (requestUrl.pathname === "/fetch") {
    const target = requestUrl.searchParams.get("url");

    if (target !== allowedTarget) {
      sendJson(response, 400, {
        error: "Only the Docker-only mock metadata endpoint is permitted"
      });
      return;
    }

    http.get(target, (upstream) => {
      let body = "";

      upstream.on("data", (chunk) => {
        body += chunk;
      });

      upstream.on("end", () => {
        response.writeHead(upstream.statusCode, {
          "Content-Type": "application/json"
        });
        response.end(body);
      });
    }).on("error", () => {
      sendJson(response, 502, {
        error: "Mock metadata service unavailable"
      });
    });

    return;
  }

  // A04 - Insecure Design simulation
  if (requestUrl.pathname === "/basket/validate") {
    const quantity = Number(
      requestUrl.searchParams.get("quantity")
    );

    sendJson(response, 200, {
      quantity,
      accepted: quantity < 0,
      persisted: false,
      note: "Non-persistent business-logic simulation"
    });

    return;
  }

  // A08 - Software and Data Integrity Failures simulation
  if (
    requestUrl.pathname === "/users/validate" &&
    request.method === "POST"
  ) {
    let body = "";

    request.on("data", (chunk) => {
      body += chunk;
    });

    request.on("end", () => {
      let input = {};

      try {
        input = JSON.parse(body || "{}");
      } catch {
        sendJson(response, 400, {
          error: "Invalid JSON"
        });
        return;
      }

      sendJson(response, 200, {
        requestedRole: input.role || "user",
        accepted: input.role === "admin",
        persisted: false,
        note: "Non-persistent integrity-validation simulation"
      });
    });

    return;
  }

  sendJson(response, 404, {
    error: "Not found"
  });

}).listen(3001, "0.0.0.0");
