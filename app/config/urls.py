"""
URL configuration for as_email_service project.
"""
from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path(
        "",
        RedirectView.as_view(pattern_name="as_email:index", permanent=True),
        name="home",
    ),
    path("as_email/", include("as_email.urls")),
]
