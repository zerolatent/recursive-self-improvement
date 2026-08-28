from physics import clamp, simulate_position, ui_slider_value


def test_clamp_restricts_upper_bound():
    assert clamp(150.0, 0.0, 100.0) == 100.0


def test_simulate_position_restricts_upper_bound():
    assert simulate_position(999.0) == 100.0


def test_ui_slider_value_restricts_upper_bound():
    assert ui_slider_value(5.0) == 1.0
