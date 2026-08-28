# Bug: duplicate accounts differ only by email capitalization

Two accounts were created for `foo@bar.com` and `Foo@Bar.com`. Both `register_user` and `update_email` call a shared `normalize_email` helper, so the fix belongs in that one place, not duplicated at each call site.
