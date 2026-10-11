import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, describe, test } from "node:test";
import { isLocal, tls, withoutSslMode } from "../../src/server/db/ssl";

const saved = process.env.PGSSLROOTCERT;
afterEach(() => {
  if (saved === undefined) delete process.env.PGSSLROOTCERT;
  else process.env.PGSSLROOTCERT = saved;
});

describe("database TLS", () => {
  test("loopback hosts and sockets count as local", () => {
    for (const uri of [
      "postgresql://u@localhost:5432/db",
      "postgresql://u@127.0.0.1/db",
      "postgresql://u@[::1]:5432/db",
      "postgresql://u@/db?host=/run/postgresql",
    ]) {
      assert.equal(isLocal(uri), true, uri);
    }
  });

  test("any other host is remote", () => {
    assert.equal(isLocal("postgresql://u:p@db-hqchat.ondigitalocean.com:25060/db?sslmode=require"), false);
    assert.equal(isLocal("postgresql://u@10.0.0.5/db"), false);
    assert.equal(isLocal("not a uri"), false);
  });

  test("a remote database without a CA is refused", () => {
    delete process.env.PGSSLROOTCERT;
    assert.throws(() => tls("postgresql://u@db.example.com/db"), /PGSSLROOTCERT/);
  });

  test("a local database without a CA connects in plaintext", () => {
    delete process.env.PGSSLROOTCERT;
    assert.equal(tls("postgresql://u@127.0.0.1/db"), false);
  });

  test("a CA turns on verification for any host", () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ca-")), "ca.pem");
    fs.writeFileSync(file, "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n");
    process.env.PGSSLROOTCERT = file;
    const remote = tls("postgresql://u@db.example.com/db");
    assert.ok(remote);
    assert.equal(remote.rejectUnauthorized, true);
    assert.ok(tls("postgresql://u@localhost/db"));
  });

  test("sslmode is stripped so the CA is not overridden", () => {
    assert.equal(withoutSslMode("postgresql://h/db?sslmode=require"), "postgresql://h/db");
    assert.equal(withoutSslMode("postgresql://h/db?a=1&sslmode=require&b=2"), "postgresql://h/db?a=1&b=2");
  });
});
