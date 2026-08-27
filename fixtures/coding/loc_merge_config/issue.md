# Bug: worker config lost its db.host after a partial override

`load_service_config` and `load_worker_config` both call the shared `merge_dicts` helper, which does a shallow `dict.update` instead of merging nested dicts. Fix the helper.
