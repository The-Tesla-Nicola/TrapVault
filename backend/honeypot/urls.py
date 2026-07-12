from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("django-admin/", admin.site.urls),
    # Monitoring dashboard (protected by JWT)
    path("monitor/", include("core.urls_monitor")),
    # Honeypot deception API (the traps)
    path("api/", include("core.urls")),
]
