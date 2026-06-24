from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from security import api_views

urlpatterns = [
    path('admin/', admin.site.urls),
    # Auth
    path('api/token/',          TokenObtainPairView.as_view(), name='token_obtain'),
    path('api/token/refresh/',  TokenRefreshView.as_view(),    name='token_refresh'),
    path('api/auth/signup/',    api_views.signup,               name='signup'),
    # Scanning
    path('api/scan/url/',       api_views.scan_url,             name='scan_url'),
    path('api/scan/bulk/',      api_views.scan_bulk,            name='scan_bulk'),
    path('api/scan/qr/',        api_views.scan_qr,              name='scan_qr'),
    path('api/scan/clear-cache/', api_views.clear_cache,        name='clear_cache'),
    # History
    path('api/history/',                api_views.history,      name='history'),
    path('api/history/<int:scan_id>/',  api_views.delete_scan,  name='delete_scan'),
    # Report + Analytics
    path('api/report/<int:scan_id>/',   api_views.report,       name='report'),
    path('api/analytics/',              api_views.analytics,    name='analytics'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
