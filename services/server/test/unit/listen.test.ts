// Bind addresses (src/common/listen.ts): an empty list means every interface,
// and a list binds each address and only those.

import assert from "node:assert/strict";
import * as http from "node:http";
import * as net from "node:net";
import { test } from "node:test";
import { listenOn, parseHosts } from "../../src/common/listen";

test("unset or blank means one server on every interface", () => {
  assert.deepEqual(parseHosts(undefined), [undefined]);
  assert.deepEqual(parseHosts(""), [undefined]);
  assert.deepEqual(parseHosts(" , "), [undefined]);
});

test("a list is split, trimmed, and keeps its order", () => {
  assert.deepEqual(parseHosts("127.0.0.1, 10.200.0.1"), ["127.0.0.1", "10.200.0.1"]);
});

test("each listed address gets its own server on the same port", async () => {
  // Grab a free port, then bind it on two loopback spellings that are distinct
  // addresses (IPv4 and IPv6 loopback).
  const probe = net.createServer().listen(0, "127.0.0.1");
  await new Promise((r) => probe.once("listening", r));
  const port = (probe.address() as net.AddressInfo).port;
  await new Promise((r) => probe.close(r));

  const bound: string[] = [];
  const servers = listenOn(
    () => http.createServer((_req, res) => res.end("ok")),
    port,
    ["127.0.0.1", "::1"],
    (host) => bound.push(host),
  );
  try {
    await Promise.all(servers.map((s) => (s.listening ? null : new Promise((r) => s.once("listening", r)))));
    assert.deepEqual(bound.sort(), ["127.0.0.1", "::1"]);
    assert.deepEqual(servers.map((s) => (s.address() as net.AddressInfo).address).sort(), ["127.0.0.1", "::1"]);
    const body = await new Promise<string>((resolve, reject) => {
      http
        .get({ host: "127.0.0.1", port }, (res) => {
          let b = "";
          res.on("data", (c) => (b += c)).on("end", () => resolve(b));
        })
        .on("error", reject);
    });
    assert.equal(body, "ok");
  } finally {
    await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  }
});
