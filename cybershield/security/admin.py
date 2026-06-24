from django.contrib import admin
from security.models import URLScan, QRScan, ScanReport

@admin.register(URLScan)
class URLScanAdmin(admin.ModelAdmin):
    list_display  = ['url', 'ml_label', 'threat_level', 'final_risk_score', 'submitted_at', 'user']
    list_filter   = ['threat_level', 'ml_label']
    search_fields = ['url']
    readonly_fields = ['submitted_at']

@admin.register(QRScan)
class QRScanAdmin(admin.ModelAdmin):
    list_display  = ['filename', 'decoded_url', 'decode_success', 'submitted_at', 'user']
    list_filter   = ['decode_success']
    readonly_fields = ['submitted_at']

@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display  = ['url_scan', 'vt_malicious', 'gsb_is_safe', 'pt_in_database', 'generated_at']
    readonly_fields = ['generated_at']
