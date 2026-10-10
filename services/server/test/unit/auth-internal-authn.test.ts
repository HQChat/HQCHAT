// The two MQTT authentication hooks, and the one line between them.
//
// The broker's internal listener allows WILDCARD subscriptions — the
// push-bridge needs `u/+/presence` and `$share/…/cv/+` — and every other
// listener refuses them, which is what keeps anybody from subscribing to `cv/+`
// and reading every conversation. So the hooks must never cross:
//
//   /mqtt/authn/internal   the internal identity, and NOTHING else
//   /mqtt/authn            everybody else, and NEVER a superuser
//
// A superuser also bypasses the static ACL, so the internal secret presented on
// a public listener must be refused, not merely demoted.

import assert from "node:assert/strict";
import { test } from "node:test";
import { createAuthHandler, INTERNAL_MQTT_USER as INTERNAL_USER } from "../../src/server/auth";
import { call } from "../helpers/http";

const INTERNAL_SECRET = "internal-secret-for-tests-only";

const authn = (path: string, body: unknown) =>
  call(createAuthHandler({ internalMqttSecret: INTERNAL_SECRET }), "POST", path, { body });

test("the internal hook admits the internal identity as a superuser", async () => {
  const r = await authn("/mqtt/authn/internal", { username: INTERNAL_USER, password: INTERNAL_SECRET });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { result: "allow", is_superuser: true });
});

test("the internal hook refuses everything else, including a wrong secret", async () => {
  for (const body of [
    {},
    { username: INTERNAL_USER, password: "" },
    { username: INTERNAL_USER, password: `${INTERNAL_SECRET}x` },
    { username: "someone-else", password: INTERNAL_SECRET },
  ]) {
    const r = await authn("/mqtt/authn/internal", body);
    assert.equal(r.status, 200, "EMQX needs a 200 even to be told no");
    assert.equal(r.body.result, "deny", JSON.stringify(body));
    assert.notEqual(r.body.is_superuser, true);
  }
});

test("the public hook never grants superuser — not even to the internal secret", async () => {
  const r = await authn("/mqtt/authn", { username: INTERNAL_USER, password: INTERNAL_SECRET, clientid: "x" });
  assert.equal(r.status, 200);
  assert.equal(r.body.result, "deny", "the internal secret opened a public-listener session");
  assert.notEqual(r.body.is_superuser, true);
});
