# slugify() mangles whitespace and separators

`slugify` builds URL slugs from user-typed titles. Users report two
classes of broken slug:

- Leading/trailing whitespace becomes leading/trailing dashes:
  `"  Hello World  "` produces `-hello-world-` instead of `hello-world`.
- Runs of non-alphanumeric characters between words produce repeated
  dashes: `"a - b"` produces `a---b` instead of `a-b`.

`slugify.test.js` encodes the expected behavior. Fix `slugify.js` so the
whole suite passes without changing the tests.
