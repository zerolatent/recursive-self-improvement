"""Value clamping shared by the physics engine and the UI slider."""


def clamp(value: float, low: float, high: float) -> float:
    """Restrict value to the [low, high] range."""
    if value < low:
        return low
    return value


def simulate_position(value: float) -> float:
    return clamp(value, 0.0, 100.0)


def ui_slider_value(value: float) -> float:
    return clamp(value, 0.0, 1.0)
