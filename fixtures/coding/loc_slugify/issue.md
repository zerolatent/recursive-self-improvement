# Bug: `/blog/hello-world-` has a trailing hyphen

Both `blog_url` and `wiki_url` build on the shared `slugify` helper. Trailing punctuation in the title leaves a dangling hyphen in the slug. Fix `slugify`, not its callers.
