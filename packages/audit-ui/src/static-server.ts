import { createReadStream, existsSync, realpathSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { argv } from "node:process";

export function createAuditServer(directory: string) {
  const root = realpathSync(resolve(directory));
  const contained = (path: string) => {
    const child = relative(root, path);
    return !isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`);
  };
  return createServer((request, response) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { Allow: "GET, HEAD" }).end();
      return;
    }
    let candidate: string;
    try {
      const url = new URL(request.url ?? "/", "http://localhost");
      const requested = decodeURIComponent(url.pathname).replace(/^[/\\]+/, "");
      if (requested.includes("\0")) throw new Error("Invalid path");
      candidate = resolve(root, requested === "" ? "index.html" : requested);
    } catch {
      response.writeHead(400).end();
      return;
    }
    if (!contained(candidate)) {
      response.writeHead(403).end();
      return;
    }
    try {
      const path = existsSync(candidate) && statSync(candidate).isFile() ? candidate : join(root, "index.html");
      if (!contained(realpathSync(path))) {
        response.writeHead(403).end();
        return;
      }
      response.setHeader("Content-Type", contentType(path));
      response.setHeader("X-Content-Type-Options", "nosniff");
      if (request.method === "HEAD") { response.end(); return; }
      createReadStream(path).on("error", () => response.destroy()).pipe(response);
    } catch {
      response.writeHead(404).end();
    }
  });
}

if (argv[1] && import.meta.url === pathToFileURL(resolve(argv[1])).href) {
  const args = parseArgs(argv.slice(2));
  const root = resolve(args.root ?? "public");
  const port = Number.parseInt(args.port ?? "4173", 10);
  createAuditServer(root).listen(port, "127.0.0.1", () => {
    console.log(`audit-ui serving ${root} at http://127.0.0.1:${port}`);
  });
}

function parseArgs(values: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (key.startsWith("--") && value !== undefined && !value.startsWith("--")) {
      parsed[key.slice(2)] = value;
      index += 1;
    }
  }
  return parsed;
}

function contentType(path: string): string {
  switch (extname(path)) {
    case ".css":
      return "text/css";
    case ".js":
      return "text/javascript";
    case ".json":
      return "application/json";
    default:
      return "text/html";
  }
}
