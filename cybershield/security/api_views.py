"""
CyberShield — DRF API Views v2
Improvements: scan caching, bulk scanning, pagination, better errors
"""
import json, re, hashlib
from django.contrib.auth.models import User
from django.core.cache import cache
from django.conf import settings as django_settings
from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status

from security.models import URLScan, QRScan, ScanReport
from security.serializers import URLScanSerializer, QRScanSerializer


# ── Helpers ───────────────────────────────────────────────────────────────────
def _threat_key(level: str) -> str:
    return level.lower().replace(' ', '_')


def _cache_key(url: str) -> str:
    """Deterministic cache key for a URL scan result."""
    return 'scan:' + hashlib.sha256(url.encode()).hexdigest()[:32]


def _save_report(url_scan, scan_result):
    ti  = scan_result.get('threat_intel', {})
    vt  = ti.get('virustotal', {})
    gsb = ti.get('google_safebrowsing', {})
    pt  = ti.get('phishtank', {})
    ab  = ti.get('abuseipdb', {})
    heu = scan_result.get('heuristic', {})

    abuse_ip = None
    raw_ip   = ab.get('ip_address')
    if raw_ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(raw_ip)):
        abuse_ip = raw_ip

    ScanReport.objects.update_or_create(
        url_scan=url_scan,
        defaults=dict(
            vt_malicious    = vt.get('malicious', 0),
            vt_suspicious   = vt.get('suspicious', 0),
            vt_harmless     = vt.get('harmless', 0),
            vt_total        = vt.get('total_engines', 0),
            vt_permalink    = vt.get('permalink') or '',
            gsb_is_safe     = gsb.get('is_safe', True),
            gsb_threats     = json.dumps(gsb.get('threat_types', [])),
            pt_in_database  = pt.get('in_database', False),
            pt_verified     = pt.get('verified', False),
            abuse_confidence= ab.get('abuse_confidence', 0),
            abuse_ip        = abuse_ip,
            abuse_country   = ab.get('country_code', ''),
            heuristic_score = heu.get('heuristic_score', 0),
            recommendation  = scan_result.get('recommendation', ''),
        )
    )


def _run_scan(url: str, user=None, include_ti: bool = True, use_cache: bool = True):
    """
    Core scan pipeline with caching.
    Returns (scan_result_dict, error_string_or_None)
    """
    from ml_engine.predictor import predict, is_model_ready
    from threat_intel.aggregator import full_scan

    if not is_model_ready():
        return None, 'ML model not found. Run: python scripts/train_model.py'

    ck     = _cache_key(url)
    cached = cache.get(ck) if use_cache else None

    if cached:
        cached_result = json.loads(cached)
        ml_pred = cached_result.get('ml_prediction', {})
        url_scan = URLScan.objects.create(
            user              = user,
            url               = url,
            ml_label          = ml_pred.get('label', 'benign'),
            ml_confidence     = ml_pred.get('confidence', 0),
            ml_risk_score     = ml_pred.get('ml_risk_score', 0),
            final_risk_score  = cached_result.get('final_risk_score', 0),
            threat_level      = _threat_key(cached_result.get('threat_level', 'safe')),
            threat_intel_json = json.dumps(cached_result.get('threat_intel', {})),
            features_json     = json.dumps(ml_pred.get('features', {})),
            heuristic_json    = json.dumps(cached_result.get('heuristic', {})),
        )
        _save_report(url_scan, cached_result)   # ← add this line

        result = cached_result
        result['scan_id']    = url_scan.pk
        result['from_cache'] = True
        return result, None

    # Fresh scan
    ml_result   = predict(url)
    scan_result = full_scan(url, ml_result, include_ti=include_ti)

    # Guarantee ml_prediction is nested in the result, regardless of
    # whether full_scan() already merges it in.
    scan_result.setdefault('ml_prediction', ml_result)

    threat_level_key = _threat_key(scan_result['threat_level'])
    url_scan = URLScan.objects.create(
        user              = user,
        url               = url,
        ml_label          = ml_result['label'],
        ml_confidence     = ml_result['confidence'],
        ml_risk_score     = ml_result['ml_risk_score'],
        final_risk_score  = scan_result['final_risk_score'],
        threat_level      = threat_level_key,
        threat_intel_json = json.dumps(scan_result.get('threat_intel', {})),
        features_json     = json.dumps(ml_result.get('features', {})),
        heuristic_json    = json.dumps(scan_result.get('heuristic', {})),
    )
    _save_report(url_scan, scan_result)

    # Cache the EXACT nested structure we just returned to the caller —
    # not a hand-rolled flat subset. This is what keeps cache-hit and
    # cache-miss responses identical in shape.
    cache.set(ck, json.dumps(scan_result), getattr(django_settings, 'SCAN_CACHE_SECONDS', 3600))

    scan_result['scan_id']    = url_scan.pk
    scan_result['from_cache'] = False
    return scan_result, None
    # Cache the raw data for repeat scans
    cache_payload = {
        'ml_label':         ml_result['label'],
        'ml_confidence':    ml_result['confidence'],
        'ml_risk_score':    ml_result['ml_risk_score'],
        'final_risk_score': scan_result['final_risk_score'],
        'threat_level':     scan_result['threat_level'],
        'threat_level_key': threat_level_key,
        'threat_emoji':     scan_result.get('threat_emoji', ''),
        'recommendation':   scan_result.get('recommendation', ''),
        'threat_intel_json':json.dumps(scan_result.get('threat_intel', {})),
        'features_json':    json.dumps(ml_result.get('features', {})),
        'heuristic_json':   json.dumps(scan_result.get('heuristic', {})),
        'component_scores': scan_result.get('component_scores', {}),
    }
    cache.set(ck, json.dumps(cache_payload), getattr(django_settings, 'SCAN_CACHE_SECONDS', 3600))

    scan_result['scan_id']    = url_scan.pk
    scan_result['from_cache'] = False
    return scan_result, None


def _normalize_url(url: str) -> str:
    url = url.strip()
    if url and not re.match(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url
    return url


# ── Auth ──────────────────────────────────────────────────────────────────────
@api_view(['POST'])
@permission_classes([AllowAny])
def signup(request):
    username = request.data.get('username', '').strip()
    password = request.data.get('password', '')
    email    = request.data.get('email', '')

    if not username or not password:
        return Response({'error': 'Username and password required'}, status=400)
    if len(password) < 8:
        return Response({'error': 'Password must be at least 8 characters'}, status=400)
    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already taken'}, status=400)

    User.objects.create_user(username=username, email=email, password=password)
    return Response({'message': 'Account created'}, status=201)


# ── Single URL Scan ───────────────────────────────────────────────────────────
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def scan_url(request):
    url = _normalize_url(request.data.get('url', ''))
    if not url:
        return Response({'error': 'URL is required'}, status=400)

    force_refresh = request.data.get('force_refresh', False)
    result, error = _run_scan(url, user=request.user, include_ti=True, use_cache=not force_refresh)
    if error:
        return Response({'error': error}, status=500)
    return Response(result)


# ── Bulk URL Scan (up to 20 URLs at once) ────────────────────────────────────
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def scan_bulk(request):
    """
    Accepts: { "urls": ["url1", "url2", ...] }  max 20 URLs
    Returns: list of scan results
    """
    raw_urls = request.data.get('urls', [])
    if not raw_urls:
        return Response({'error': 'No URLs provided'}, status=400)
    if len(raw_urls) > 20:
        return Response({'error': 'Maximum 20 URLs per bulk scan'}, status=400)

    results = []
    for raw in raw_urls:
        url = _normalize_url(str(raw))
        if not url:
            results.append({'url': raw, 'error': 'Invalid URL'})
            continue
        result, error = _run_scan(url, user=request.user, include_ti=True, use_cache=True)
        if error:
            results.append({'url': url, 'error': error})
        else:
            results.append(result)

    return Response(results)


# ── QR Scan ───────────────────────────────────────────────────────────────────
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def scan_qr(request):
    files = request.FILES.getlist('qr_images')
    if not files:
        return Response({'error': 'No images uploaded'}, status=400)

    from qr_scanner.decoder import decode_qr
    results = []

    for f in files:
        decode = decode_qr(f.read())
        entry  = {'filename': f.name, 'decode': decode, 'scan': None, 'error': None}

        if decode['success'] and decode.get('data'):
            decoded_url = _normalize_url(decode['data'])
            scan_result, err = _run_scan(decoded_url, user=request.user, include_ti=True)
            if err:
                entry['error'] = err
            else:
                url_scan_obj = URLScan.objects.filter(pk=scan_result.get('scan_id')).first()
                QRScan.objects.create(
                    user=request.user, filename=f.name,
                    decode_success=True, decoded_url=decoded_url, url_scan=url_scan_obj,
                )
                entry['scan'] = scan_result
        else:
            entry['error'] = decode.get('error', 'QR decode failed')
            QRScan.objects.create(
                user=request.user, filename=f.name,
                decode_success=False, decode_error=entry['error'],
            )
        results.append(entry)

    return Response(results)


# ── History (paginated) ───────────────────────────────────────────────────────
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def history(request):
    qs = URLScan.objects.filter(user=request.user).order_by('-submitted_at')

    q        = request.GET.get('q', '').strip()
    level    = request.GET.get('level', '').strip()
    page     = max(1, int(request.GET.get('page', 1)))
    per_page = min(50, int(request.GET.get('per_page', 25)))

    if q:     qs = qs.filter(url__icontains=q)
    if level: qs = qs.filter(threat_level=level)

    total = qs.count()
    start = (page - 1) * per_page
    items = qs[start: start + per_page]

    return Response({
        'results':   URLScanSerializer(items, many=True).data,
        'total':     total,
        'page':      page,
        'per_page':  per_page,
        'has_next':  start + per_page < total,
    })


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_scan(request, scan_id):
    try:
        URLScan.objects.get(pk=scan_id, user=request.user).delete()
        return Response({'success': True})
    except URLScan.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)


# ── Report ────────────────────────────────────────────────────────────────────
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def report(request, scan_id):
    try:
        scan = URLScan.objects.get(pk=scan_id, user=request.user)
    except URLScan.DoesNotExist:
        return Response({'error': 'Report not found'}, status=404)

    data = URLScanSerializer(scan).data
    try:
        data['recommendation'] = scan.report.recommendation
    except Exception:
        pass
    return Response(data)


# ── Analytics ─────────────────────────────────────────────────────────────────
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def analytics(request):
    qs = URLScan.objects.filter(user=request.user)

    total    = qs.count()
    avg_risk = round(qs.aggregate(a=Avg('final_risk_score'))['a'] or 0, 1)

    by_threat   = list(qs.values('threat_level').annotate(count=Count('id')))
    by_ml_label = list(qs.values('ml_label').annotate(count=Count('id')))

    thirty_ago = timezone.now() - timedelta(days=30)
    daily = list(
        qs.filter(submitted_at__gte=thirty_ago)
        .extra(select={'day': "date(submitted_at)"})
        .values('day')
        .annotate(count=Count('id'), avg_score=Avg('final_risk_score'))
        .order_by('day')
    )

    top_threats = list(
        qs.filter(threat_level__in=['malicious', 'high_risk'])
        .order_by('-final_risk_score')
        .values('id','url','ml_label','final_risk_score','threat_level','submitted_at')[:10]
    )

    recent = list(
        qs.order_by('-submitted_at')
        .values('id','url','ml_label','final_risk_score','threat_level','submitted_at')[:8]
    )

    # Risk score distribution
    risk_dist = {
        'safe':       qs.filter(final_risk_score__lte=20).count(),
        'low_risk':   qs.filter(final_risk_score__gt=20, final_risk_score__lte=40).count(),
        'suspicious': qs.filter(final_risk_score__gt=40, final_risk_score__lte=60).count(),
        'high_risk':  qs.filter(final_risk_score__gt=60, final_risk_score__lte=80).count(),
        'malicious':  qs.filter(final_risk_score__gt=80).count(),
    }

    return Response({
        'total':      total,
        'avg_risk':   avg_risk,
        'by_threat':  by_threat,
        'by_ml_label':by_ml_label,
        'daily':      daily,
        'top_threats':top_threats,
        'recent':     recent,
        'risk_dist':  risk_dist,
    })


# ── Cache clear for a URL ─────────────────────────────────────────────────────
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def clear_cache(request):
    url = _normalize_url(request.data.get('url', ''))
    if url:
        cache.delete(_cache_key(url))
    return Response({'success': True})
