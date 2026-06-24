from rest_framework import serializers
from security.models import URLScan, QRScan, ScanReport
import json

class URLScanSerializer(serializers.ModelSerializer):
    features       = serializers.SerializerMethodField()
    threat_intel   = serializers.SerializerMethodField()
    heuristic      = serializers.SerializerMethodField()
    component_scores = serializers.SerializerMethodField()
    recommendation = serializers.SerializerMethodField()

    class Meta:
        model  = URLScan
        fields = [
            'id','url','ml_label','ml_confidence','ml_risk_score',
            'final_risk_score','threat_level','submitted_at',
            'features','threat_intel','heuristic','component_scores','recommendation',
        ]

    def _parse(self, obj, field):
        try:
            raw = getattr(obj, field, '{}') or '{}'
            return json.loads(raw)
        except Exception:
            return {}

    def get_features(self, obj):    return self._parse(obj, 'features_json')
    def get_threat_intel(self, obj):return self._parse(obj, 'threat_intel_json')
    def get_heuristic(self, obj):   return self._parse(obj, 'heuristic_json')

    def get_component_scores(self, obj):
        ti = self._parse(obj, 'threat_intel_json')
        return {
            'ml_model':            obj.ml_risk_score,
            'virustotal':          ti.get('virustotal',{}).get('risk_score', 0),
            'google_safe_browsing':ti.get('google_safebrowsing',{}).get('risk_score', 0),
            'phishtank':           ti.get('phishtank',{}).get('risk_score', 0),
            'abuseipdb':           ti.get('abuseipdb',{}).get('risk_score', 0),
            'urlscan':             ti.get('urlscan',{}).get('risk_score', 0),
            'heuristic':           self._parse(obj,'heuristic_json').get('heuristic_score', 0),
        }

    def get_recommendation(self, obj):
        try:
            report = obj.report
            return report.recommendation if report else ''
        except Exception:
            return ''


class QRScanSerializer(serializers.ModelSerializer):
    url_scan = URLScanSerializer(read_only=True)
    class Meta:
        model  = QRScan
        fields = ['id','filename','decoded_url','decode_success','decode_error','submitted_at','url_scan']
