import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { createAuditServer } from "../src/static-server.ts";

test("static UI confines encoded paths and symlinks to its root", async () => {
  const temp = mkdtempSync(join(tmpdir(), "govreplay-ui-"));
  const root = join(temp, "public");
  mkdirSync(root);
  mkdirSync(join(temp, "public-private"));
  writeFileSync(join(root, "index.html"), "safe UI");
  writeFileSync(join(temp, "public-private", "secret.txt"), "outside-root");
  symlinkSync(join(temp, "public-private", "secret.txt"), join(root, "linked.txt"));
  const server = createAuditServer(root);
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const read = (path: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    request({ host: "127.0.0.1", port: address.port, path }, response => {
      let body = "";
      response.on("data", data => body += data);
      response.on("end", () => resolve({ status: response.statusCode!, body }));
    }).on("error", reject).end();
  });
  try {
    assert.deepEqual(await read("/"), { status: 200, body: "safe UI" });
    assert.equal((await read("/..%2fpublic-private%2fsecret.txt")).status, 403);
    assert.equal((await read("/linked.txt")).status, 403);
    assert.equal((await read("/%zz")).status, 400);
    assert.equal((await read("/%00")).status, 400);
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    rmSync(temp, { recursive: true, force: true });
  }
});
