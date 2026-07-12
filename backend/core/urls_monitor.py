from django.urls import path
from django.shortcuts import render, redirect

from . import views_monitor as m
from . import views_siem as siem


def _siem_dashboard_html(request):
    """Serve the SIEM single-page dashboard."""
    return render(request, "siem/dashboard.html")


urlpatterns = [
    path("", lambda r: redirect("siem_dashboard"), name="monitor_root"),
    # -------------------------------------------------------------------------
    # Monitor Authentication (Token management) - No 'api/' prefix for tests
    # -------------------------------------------------------------------------
    path("auth/login/", m.monitor_login, name="monitor_login"),
    path("auth/refresh/", m.monitor_refresh_token, name="monitor_refresh"),
    path("auth/logout/", m.monitor_logout, name="monitor_logout"),
    # -------------------------------------------------------------------------
    # HTML Pages (Operator views)
    # -------------------------------------------------------------------------
    path("login/", _siem_dashboard_html, name="monitor_login_page"),
    path("siem/", _siem_dashboard_html, name="siem_dashboard"),
    path("real-bank/", m.real_bank_dashboard, name="real_bank_dashboard"),
    # -------------------------------------------------------------------------
    # Core Monitoring API (Stats, Events, Sessions) - With 'api/' prefix
    # -------------------------------------------------------------------------
    path("api/stats/", m.api_stats_overview, name="api_stats"),
    path("api/events/", m.api_events_list, name="api_events"),
    path("api/sessions/", m.api_sessions_list, name="api_sessions"),
    path(
        "api/sessions/<uuid:session_id>/",
        m.api_session_detail,
        name="api_session_detail",
    ),
    path(
        "api/sessions/<uuid:session_id>/action/",
        m.api_session_action,
        name="api_session_action",
    ),
    path("api/credentials/", m.api_credentials_list, name="api_credentials"),
    path("api/threat-intel/", m.api_threat_intel, name="api_threat_intel"),
    path("api/realtime/", m.api_realtime_events, name="api_realtime"),
    path("api/export/", m.api_export_data, name="api_export"),
    # -------------------------------------------------------------------------
    # Advanced SIEM API (SIEM-specific dashboards) - With 'api/' prefix
    # -------------------------------------------------------------------------
    path("api/siem/overview/", siem.siem_overview, name="siem_overview"),
    path("api/siem/live/", siem.siem_live_feed, name="siem_live"),
    path("api/siem/alerts/", siem.siem_alert_queue, name="siem_alerts"),
    path(
        "api/siem/alerts/<uuid:alert_id>/ack/",
        siem.siem_acknowledge_alert,
        name="siem_ack",
    ),
    path("api/siem/alerts/bulk-ack/", siem.siem_bulk_acknowledge, name="siem_bulk_ack"),
    path("api/siem/funnel/", siem.siem_login_funnel, name="siem_funnel"),
    path("api/siem/heatmap/", siem.siem_heatmap, name="siem_heatmap"),
    path("api/siem/rules/", siem.siem_alert_rules, name="siem_rules"),
    path(
        "api/siem/rules/<uuid:rule_id>/",
        siem.siem_alert_rule_detail,
        name="siem_rule_detail",
    ),
    path(
        "api/siem/timeline/<str:fingerprint>/",
        siem.siem_session_timeline,
        name="siem_timeline",
    ),
    path("api/siem/iocs/", siem.siem_ioc_feed, name="siem_iocs"),
    path("api/siem/real-users/", siem.real_bank_users, name="siem_real_users"),
    # Professional Upgrade: ML, Threat Intel, SOAR
    path(
        "api/siem/ml-anomaly/<uuid:session_id>/",
        siem.get_ml_anomaly,
        name="siem_ml_anomaly",
    ),
    path(
        "api/siem/threat-intel/<str:ip_address>/",
        siem.get_threat_intel,
        name="siem_threat_intel_detail",
    ),
    path(
        "api/soar/block/<uuid:session_id>/", siem.block_session_api, name="soar_block"
    ),
    path(
        "api/soar/unblock/<uuid:session_id>/",
        siem.unblock_session_api,
        name="soar_unblock",
    ),
    path("api/soar/stats/", siem.get_soar_stats_api, name="soar_stats"),
]
