# Bug: slider value goes above 1.0

`simulate_position` and `ui_slider_value` both call the shared `clamp` helper, which checks the lower bound but never the upper one. Fix the helper.
