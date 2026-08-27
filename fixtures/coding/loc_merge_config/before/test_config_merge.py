from config_merge import load_service_config, load_worker_config, merge_dicts

BASE = {"db": {"host": "localhost", "port": 5432}, "debug": False}
OVERRIDE = {"db": {"port": 6543}}


def test_merge_dicts_preserves_nested_keys():
    result = merge_dicts(BASE, OVERRIDE)
    assert result == {"db": {"host": "localhost", "port": 6543}, "debug": False}


def test_load_service_config_preserves_nested_keys():
    assert load_service_config(BASE, OVERRIDE)["db"]["host"] == "localhost"


def test_load_worker_config_preserves_nested_keys():
    assert load_worker_config(BASE, OVERRIDE)["db"]["host"] == "localhost"
