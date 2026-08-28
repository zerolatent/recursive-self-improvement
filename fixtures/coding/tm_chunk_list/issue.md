# Bug: the last item in a 5-item batch of size 2 never gets sent

`chunk`'s range excludes the short final chunk instead of including it.
