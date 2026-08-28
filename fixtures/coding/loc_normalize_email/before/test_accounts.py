from accounts import normalize_email, register_user, update_email


def test_normalize_email_lowercases():
    assert normalize_email("  Foo@Bar.com ") == "foo@bar.com"


def test_register_user_uses_normalized_email():
    assert register_user("Foo@Bar.com") == "foo@bar.com"


def test_update_email_uses_normalized_email():
    assert update_email("FOO@BAR.COM") == "foo@bar.com"
