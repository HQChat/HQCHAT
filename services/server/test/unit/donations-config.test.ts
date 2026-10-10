import assert from "node:assert/strict";
import { test } from "node:test";
import {
  DONATION_ONCE_VAR,
  DONATION_TIERS_VAR,
  donationGaps,
  donationSummary,
  donationsDead,
  resolvePrices,
} from "../../src/server/donations-config";

test("prices come from the environment, in order", () => {
  const p = resolvePrices({ [DONATION_TIERS_VAR]: "price_a, price_b,price_c", [DONATION_ONCE_VAR]: " price_once " });
  assert.deepEqual(p, { tiers: ["price_a", "price_b", "price_c"], once: "price_once" });
  assert.deepEqual(donationGaps(p), []);
  assert.equal(donationsDead(p), false);
});

test("anything that is not a Stripe price id is ignored", () => {
  const p = resolvePrices({ [DONATION_TIERS_VAR]: "prod_x,,price_a, ", [DONATION_ONCE_VAR]: "sku_y" });
  assert.deepEqual(p, { tiers: ["price_a"], once: "" });
  assert.deepEqual(donationGaps(p), [DONATION_ONCE_VAR]);
});

test("nothing configured is reported as dead, naming both variables", () => {
  const p = resolvePrices({});
  assert.equal(donationsDead(p), true);
  assert.match(donationSummary(p), new RegExp(`${DONATION_TIERS_VAR}.*${DONATION_ONCE_VAR}`));
});

test("no price id appears in a message that may reach a log", () => {
  for (const p of [resolvePrices({}), { tiers: ["price_x"], once: "" }, { tiers: [], once: "price_y" }]) {
    assert.doesNotMatch(donationSummary(p), /price_[A-Za-z0-9]/);
  }
});
