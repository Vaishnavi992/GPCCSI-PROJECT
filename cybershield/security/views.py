"""
Security App Views
==================
All views for the CyberShield cybersecurity platform.
"""
import json, re, os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta

from security.models import URLScan, QRScan, ScanReport


# ── Helper: Convert threat_level string to key ────────────────────────────────
def _threat_key(level: str) -> str:
    return level.lower().replace(' ', '_')


def _save_scan_report(url_scan, scan_result):
    """Persist detailed report to ScanReport table."""
    ti = scan_result.get('threat_intel', {})
    vt = ti.get('virustotal', {})
    gsb = ti.get('google_safebrowsing', {})
    pt  = ti.get('phishtank', {})
    ab  = ti.get('abuseipdb', {})
    heu = scan_result.get('heuristic', {})

    abuse_ip = None
    raw_ip   = ab.get('ip_address')
    if raw_ip and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(raw_ip)):
        abuse_ip = raw_ip

    report, _ = ScanReport.objects.update_or_create(
        url_scan=url_scan,
        defaults=dict(
            vt_malicious   = vt.get('malicious', 0),
            vt_suspicious  = vt.get('suspicious', 0),
            vt_harmless    = vt.get('harmless', 0),
            vt_total       = vt.get('total_engines', 0),
            vt_permalink   = vt.get('permalink') or '',
            gsb_is_safe    = gsb.get('is_safe', True),
            gsb_threats    = json.dumps(gsb.get('threat_types', [])),
            pt_in_database = pt.get('in_database', False),
            pt_verified    = pt.get('verified', False),
            abuse_confidence= ab.get('abuse_confidence', 0),
            abuse_ip       = abuse_ip,
            abuse_country  = ab.get('country_code', ''),
            heuristic_score= heu.get('heuristic_score', 0),
            recommendation = scan_result.get('recommendation', ''),
        )
    )
    return report


def _run_full_scan(url: str, user=None, include_ti: bool = True):
    """
    Core scan pipeline:
    URL → Feature Extraction → ML Prediction → TI Checks → Risk Score → Report
    """
    from ml_engine.predictor import predict, is_model_ready
    from threat_intel.aggregator import full_scan

    if not is_model_ready():
        return None, 'ML model not found. Run: python scripts/train_model.py'

    # Step 1: ML prediction
    ml_result = predict(url)

    # Step 2: Aggregate with TI
    scan_result = full_scan(url, ml_result, include_ti=include_ti)

    # Step 3: Persist to database
    threat_level_key = _threat_key(scan_result['threat_level'])
    url_scan = URLScan.objects.create(
        user             = user,
        url              = url,
        ml_label         = ml_result['label'],
        ml_confidence    = ml_result['confidence'],
        ml_risk_score    = ml_result['ml_risk_score'],
        final_risk_score = scan_result['final_risk_score'],
        threat_level     = threat_level_key,
        threat_intel_json= json.dumps(scan_result.get('threat_intel', {})),
        features_json    = json.dumps(ml_result.get('features', {})),
        heuristic_json   = json.dumps(scan_result.get('heuristic', {})),
    )
    _save_scan_report(url_scan, scan_result)

    # Attach db id for template use
    scan_result['scan_id'] = url_scan.pk
    return scan_result, None


# ── Public Views ──────────────────────────────────────────────────────────────
def home(request):
    return render(request, 'security/home.html')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect(request.GET.get('next', 'dashboard'))
        error = 'Invalid username or password.'
    return render(request, 'registration/login.html', {'error': error})


def signup_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    if request.method == 'POST':
        username  = request.POST.get('username', '').strip()
        email     = request.POST.get('email', '').strip()
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')
        if password1 != password2:
            error = 'Passwords do not match.'
        elif len(password1) < 8:
            error = 'Password must be at least 8 characters.'
        elif User.objects.filter(username=username).exists():
            error = 'Username already taken.'
        else:
            user = User.objects.create_user(username=username, email=email, password=password1)
            login(request, user)
            return redirect('dashboard')
    return render(request, 'registration/signup.html', {'error': error})


def logout_view(request):
    logout(request)
    return redirect('home')


# ── Authenticated Views ────────────────────────────────────────────────────────
@login_required
def dashboard(request):
    user = request.user
    total_scans = URLScan.objects.filter(user=user).count()
    total_qr    = QRScan.objects.filter(user=user).count()

    # Threat breakdown
    threat_counts = (
        URLScan.objects.filter(user=user)
        .values('threat_level')
        .annotate(count=Count('id'))
    )
    threat_map = {t['threat_level']: t['count'] for t in threat_counts}

    # Recent scans (last 5)
    recent_scans = URLScan.objects.filter(user=user).order_by('-submitted_at')[:5]

    # Trend data — last 14 days
    fourteen_days_ago = timezone.now() - timedelta(days=14)
    daily_scans = (
        URLScan.objects
        .filter(user=user, submitted_at__gte=fourteen_days_ago)
        .extra(select={'day': "date(submitted_at)"})
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    return render(request, 'security/dashboard.html', {
        'total_scans':   total_scans,
        'total_qr':      total_qr,
        'threat_counts': threat_map,
        'recent_scans':  recent_scans,
        'daily_scans':   json.dumps(list(daily_scans)),
        'malicious_pct': round(
            (threat_map.get('malicious', 0) + threat_map.get('high_risk', 0)) /
            max(total_scans, 1) * 100, 1
        ),
    })


@login_required
def url_scanner(request):
    """URL scanner page — renders form or processes scan."""
    result = None
    error  = None
    url    = ''

    if request.method == 'POST':
        url = request.POST.get('url', '').strip()
        # Basic URL validation
        if not url:
            error = 'Please enter a URL to scan.'
        elif not re.match(r'^https?://', url, re.IGNORECASE):
            url = 'http://' + url  # auto-add scheme

        if url and not error:
            result, error = _run_full_scan(url, user=request.user, include_ti=True)

    return render(request, 'security/url_scanner.html', {
        'result': result, 'error': error, 'url': url,
    })


@login_required
def qr_scanner(request):
    """QR scanner page — handles image upload."""
    results = []
    error   = None

    if request.method == 'POST':
        uploaded_files = request.FILES.getlist('qr_images')
        if not uploaded_files:
            error = 'Please upload at least one QR code image.'
        else:
            from qr_scanner.decoder import decode_qr

            for f in uploaded_files:
                file_bytes = f.read()
                decode = decode_qr(file_bytes)

                qr_entry = {'filename': f.name, 'decode': decode, 'scan': None, 'error': None}

                if decode['success'] and decode['data']:
                    decoded_url = decode['data'].strip()
                    scan_result, scan_error = _run_full_scan(
                        decoded_url, user=request.user, include_ti=True
                    )
                    if scan_error:
                        qr_entry['error'] = scan_error
                    else:
                        # Save QR scan record
                        url_scan_obj = URLScan.objects.filter(pk=scan_result.get('scan_id')).first()
                        QRScan.objects.create(
                            user          = request.user,
                            filename      = f.name,
                            decode_success= True,
                            decoded_url   = decoded_url,
                            url_scan      = url_scan_obj,
                        )
                        qr_entry['scan'] = scan_result
                else:
                    qr_entry['error'] = decode.get('error', 'QR decode failed')
                    QRScan.objects.create(
                        user          = request.user,
                        filename      = f.name,
                        decode_success= False,
                        decode_error  = qr_entry['error'],
                    )

                results.append(qr_entry)

    return render(request, 'security/qr_scanner.html', {
        'results': results, 'error': error,
    })


@login_required
def scan_history(request):
    """Show all past URL + QR scans for this user."""
    filter_level = request.GET.get('level', '')
    search       = request.GET.get('q', '').strip()

    url_scans = URLScan.objects.filter(user=request.user)
    if filter_level:
        url_scans = url_scans.filter(threat_level=filter_level)
    if search:
        url_scans = url_scans.filter(url__icontains=search)
    url_scans = url_scans.order_by('-submitted_at')[:100]

    qr_scans = QRScan.objects.filter(user=request.user).order_by('-submitted_at')[:50]

    return render(request, 'security/history.html', {
        'url_scans':    url_scans,
        'qr_scans':     qr_scans,
        'filter_level': filter_level,
        'search':       search,
    })


@login_required
def analytics(request):
    """Analytics page with charts and statistics."""
    user = request.user
    all_scans = URLScan.objects.filter(user=user)

    # Threat distribution
    threat_dist = list(all_scans.values('threat_level').annotate(count=Count('id')))

    # ML label distribution
    ml_dist = list(all_scans.values('ml_label').annotate(count=Count('id')))

    # Average risk score
    avg_risk = all_scans.aggregate(avg=Avg('final_risk_score'))['avg'] or 0

    # Last 30 days trend
    thirty_days = timezone.now() - timedelta(days=30)
    daily = list(
        all_scans.filter(submitted_at__gte=thirty_days)
        .extra(select={'day': "date(submitted_at)"})
        .values('day')
        .annotate(count=Count('id'), avg_score=Avg('final_risk_score'))
        .order_by('day')
    )

    # Top malicious/phishing URLs
    top_threats = all_scans.filter(
        threat_level__in=['malicious', 'high_risk']
    ).order_by('-final_risk_score')[:10]

    return render(request, 'security/analytics.html', {
        'threat_dist': json.dumps(threat_dist),
        'ml_dist':     json.dumps(ml_dist),
        'avg_risk':    round(avg_risk, 1),
        'daily':       json.dumps(daily),
        'top_threats': top_threats,
        'total_scans': all_scans.count(),
    })


@login_required
def report_detail(request, scan_id):
    """Detailed report for a single URL scan."""
    url_scan = get_object_or_404(URLScan, pk=scan_id, user=request.user)
    report   = getattr(url_scan, 'report', None)

    # Parse stored JSON
    ti_data      = json.loads(url_scan.threat_intel_json or '{}')
    features     = json.loads(url_scan.features_json or '{}')
    heuristic    = json.loads(url_scan.heuristic_json or '{}')

    # Build threat_level label
    level_labels = {
        'safe': 'Safe', 'low_risk': 'Low Risk',
        'suspicious': 'Suspicious', 'high_risk': 'High Risk', 'malicious': 'Malicious'
    }
    level_colors = {
        'safe': '#16a34a', 'low_risk': '#2563eb',
        'suspicious': '#d97706', 'high_risk': '#dc2626', 'malicious': '#7c3aed'
    }

    return render(request, 'security/report.html', {
        'url_scan':    url_scan,
        'report':      report,
        'ti_data':     ti_data,
        'features':    features,
        'heuristic':   heuristic,
        'level_label': level_labels.get(url_scan.threat_level, 'Unknown'),
        'level_color': level_colors.get(url_scan.threat_level, '#6b7280'),
    })


# ── AJAX API Endpoints ─────────────────────────────────────────────────────────
@login_required
@require_POST
def api_scan_url(request):
    """JSON API endpoint for URL scanning (used by JS fetch)."""
    try:
        data = json.loads(request.body)
        url  = data.get('url', '').strip()
        if not url:
            return JsonResponse({'error': 'URL required'}, status=400)
        if not re.match(r'^https?://', url, re.IGNORECASE):
            url = 'http://' + url
        result, error = _run_full_scan(url, user=request.user, include_ti=True)
        if error:
            return JsonResponse({'error': error}, status=500)
        return JsonResponse({'success': True, 'result': result})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_delete_scan(request, scan_id):
    """Delete a scan from history."""
    if request.method == 'DELETE':
        scan = get_object_or_404(URLScan, pk=scan_id, user=request.user)
        scan.delete()
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'Method not allowed'}, status=405)
