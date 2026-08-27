from publishing import blog_url, slugify, wiki_url


def test_slugify_strips_trailing_punctuation():
    assert slugify("Hello, World!") == "hello-world"


def test_blog_url_has_no_trailing_hyphen():
    assert blog_url("Hello, World!") == "/blog/hello-world"


def test_wiki_url_has_no_trailing_hyphen():
    assert wiki_url("Ready?") == "/wiki/ready"
