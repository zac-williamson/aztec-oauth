import "dotenv/config";
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";

const config = loadConfig();
const server = createServer(config);

server.listen(config.port, () => {
  console.log(`OAuth proxy service listening on port ${config.port}`);
  console.log(`Service URL: ${config.serviceUrl}`);
  console.log(`Allowed origins: ${config.allowedOrigins.join(", ")}`);
  console.log(`Google OAuth: configured`);
  console.log(`Apple OAuth: ${config.apple ? "configured" : "not configured"}`);
});
