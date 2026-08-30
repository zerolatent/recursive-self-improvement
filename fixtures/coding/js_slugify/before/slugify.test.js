const test = require("node:test");
const assert = require("node:assert");
const { slugify } = require("./slugify.js");

test("trims surrounding whitespace", () => {
  assert.strictEqual(slugify("  Hello World  "), "hello-world");
});

test("collapses non-alphanumeric runs to a single dash", () => {
  assert.strictEqual(slugify("a - b"), "a-b");
});

test("keeps simple phrases intact", () => {
  assert.strictEqual(slugify("Multi   spaces"), "multi-spaces");
});
