def register_routes(app):
    from api.status import register as reg_status
    from api.logs import register as reg_logs
    from api.config_api import register as reg_config
    from api.control import register as reg_control
    from api.strategies import register as reg_strategies
    from api.hostlists import register as reg_hostlists
    from api.ipsets import register as reg_ipsets
    from api.blobs import register as reg_blobs
    from api.hosts import register as reg_hosts
    from api.diagnostics import register as reg_diagnostics
    from api.autostart import register as reg_autostart
    from api.zapret_manager import register as reg_zapret_manager
    reg_status(app)
    reg_logs(app)
    reg_config(app)
    reg_control(app)
    reg_strategies(app)
    reg_hostlists(app)
    reg_ipsets(app)
    reg_blobs(app)
    reg_hosts(app)
    reg_diagnostics(app)
    reg_autostart(app)
    reg_zapret_manager(app)
