"""
Database Models
================
URLScan   — results of scanning a URL
QRScan    — results of scanning a QR code image
ScanReport— detailed report combining ML + TI results
"""
from django.db import models
from django.contrib.auth.models import User


THREAT_LEVELS = [
    ('safe',       'Safe'),
    ('low_risk',   'Low Risk'),
    ('suspicious', 'Suspicious'),
    ('high_risk',  'High Risk'),
    ('malicious',  'Malicious'),
]

ML_LABELS = [
    ('benign',     'Benign'),
    ('defacement', 'Defacement'),
    ('phishing',   'Phishing'),
    ('malware',    'Malware'),
]


class URLScan(models.Model):
    """Result of scanning a URL."""
    user         = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='url_scans')
    url          = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)

    # ML Results
    ml_label       = models.CharField(max_length=20, choices=ML_LABELS, default='benign')
    ml_confidence  = models.FloatField(default=0.0)
    ml_risk_score  = models.IntegerField(default=0)

    # Final combined score
    final_risk_score = models.IntegerField(default=0)
    threat_level     = models.CharField(max_length=20, choices=THREAT_LEVELS, default='safe')

    # Component scores (JSON stored as text)
    threat_intel_json = models.TextField(blank=True, default='{}')
    features_json     = models.TextField(blank=True, default='{}')
    heuristic_json    = models.TextField(blank=True, default='{}')

    class Meta:
        ordering = ['-submitted_at']
        verbose_name = 'URL Scan'

    def __str__(self):
        return f'{self.url[:60]} — {self.threat_level} ({self.final_risk_score}/100)'

    @property
    def threat_label_display(self):
        return dict(THREAT_LEVELS).get(self.threat_level, self.threat_level.title())

    @property
    def risk_color(self):
        colors = {
            'safe': '#16a34a', 'low_risk': '#2563eb',
            'suspicious': '#d97706', 'high_risk': '#dc2626', 'malicious': '#7c3aed'
        }
        return colors.get(self.threat_level, '#6b7280')


class QRScan(models.Model):
    """Result of scanning a QR code image."""
    user         = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='qr_scans')
    filename     = models.CharField(max_length=255, blank=True)
    image        = models.ImageField(upload_to='qr_uploads/', null=True, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    # QR Decode results
    decoded_url  = models.TextField(blank=True)
    decode_success = models.BooleanField(default=False)
    decode_error = models.TextField(blank=True)

    # URL scan (ForeignKey to URLScan if decode succeeded)
    url_scan = models.ForeignKey(URLScan, on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        ordering = ['-submitted_at']
        verbose_name = 'QR Scan'

    def __str__(self):
        return f'{self.filename} → {self.decoded_url[:50] if self.decoded_url else "decode failed"}'


class ScanReport(models.Model):
    """
    Detailed security report combining ML prediction + all TI results.
    Generated for both URL and QR scans.
    """
    url_scan  = models.OneToOneField(URLScan, on_delete=models.CASCADE, related_name='report')
    generated_at = models.DateTimeField(auto_now_add=True)

    # Virustotal
    vt_malicious    = models.IntegerField(default=0)
    vt_suspicious   = models.IntegerField(default=0)
    vt_harmless     = models.IntegerField(default=0)
    vt_total        = models.IntegerField(default=0)
    vt_permalink    = models.URLField(blank=True)

    # Google Safe Browsing
    gsb_is_safe     = models.BooleanField(default=True)
    gsb_threats     = models.TextField(blank=True)

    # PhishTank
    pt_in_database  = models.BooleanField(default=False)
    pt_verified     = models.BooleanField(default=False)

    # AbuseIPDB
    abuse_confidence = models.IntegerField(default=0)
    abuse_ip         = models.GenericIPAddressField(null=True, blank=True)
    abuse_country    = models.CharField(max_length=10, blank=True)

    # Heuristic
    heuristic_score  = models.IntegerField(default=0)

    # Recommendation
    recommendation   = models.TextField(blank=True)

    class Meta:
        verbose_name = 'Scan Report'

    def __str__(self):
        return f'Report for {self.url_scan}'
