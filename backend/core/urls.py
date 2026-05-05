from django.urls import path, re_path
from . import views_deception as d
from . import views_siem as siem
from . import views_real_bank as rb
from .views_monitor import health_check, api_metrics
from .views_proxy import proxy_login

urlpatterns = [
    path("health/", health_check, name="health_check"),
    path("api/health/", health_check, name="api_health_check"),
    path("api/metrics/", api_metrics, name="api_metrics"),
    path("auth/login/", proxy_login, name="proxy_login"),
    path(
        "real-bank/auth/login/", rb.RealBankLoginView.as_view(), name="real_bank_login"
    ),
    path(
        "real-bank/auth/register/",
        rb.RealBankRegisterView.as_view(),
        name="real_bank_register",
    ),
    path(
        "real-bank/auth/logout/",
        rb.RealBankLogoutView.as_view(),
        name="real_bank_logout",
    ),
    path(
        "real-bank/dashboard/",
        rb.RealBankDashboardView.as_view(),
        name="real_bank_dashboard",
    ),
    path(
        "real-bank/account/", rb.RealBankAccountView.as_view(), name="real_bank_account"
    ),
    path(
        "real-bank/transfer/",
        rb.RealBankTransferView.as_view(),
        name="real_bank_transfer",
    ),
    path("admin/dashboard/", d.fake_admin_dashboard, name="fake_admin_dashboard"),
    path("admin/users/", d.fake_admin_users, name="fake_admin_users"),
    path("admin/settings/", d.fake_admin_settings, name="fake_admin_settings"),
    path("admin/backup/", d.fake_admin_backup, name="fake_admin_backup"),
    path("admin/api-keys/", d.fake_admin_api_keys, name="fake_admin_api_keys"),
    path("admin/database/", d.fake_admin_db_console, name="fake_admin_db_console"),
    path("admin/files/", d.fake_admin_file_browser, name="fake_admin_file_browser"),
    path("admin/download/", d.fake_admin_download, name="fake_admin_download"),
    path("internal/config/", d.fake_internal_config, name="fake_internal_config"),
    path("debug/env/", d.fake_internal_config, name="fake_debug_env"),
    path("search/", d.fake_search, name="fake_search"),
    path("password-reset/", d.fake_password_reset, name="fake_password_reset"),
    path("auth/verify/", d.fake_mfa_verify, name="fake_mfa_verify"),
    path("telemetry/capture/", siem.capture_telemetry, name="capture_telemetry"),
    path(".env", d.fake_file_download, {"name": ".env"}),
    path(".git/config", d.fake_file_download, {"name": ".git/config"}),
    path("wp-admin/", d.fake_admin_dashboard, name="trap_wp_admin"),
    path("phpmyadmin/", d.fake_database_console, name="trap_phpmyadmin"),
    path("actuator/", d.fake_internal_config, name="trap_actuator"),
    re_path(r"^(?P<path>.*)$", d.catch_all_api, name="catch_all"),
]
