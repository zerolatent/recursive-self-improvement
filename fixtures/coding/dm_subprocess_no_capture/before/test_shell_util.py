from shell_util import run_command


def test_run_command_captures_stdout():
    output = run_command(["echo", "hello"])
    assert output.strip() == "hello"
