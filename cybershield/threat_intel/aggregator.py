"""
Threat Intelligence Aggregator v2
===================================
Combines ML prediction + 5 TI API results into a single weighted risk score.

Scoring weights (sum = 1.0):
  ML Model           40%
  VirusTotal         25%
  Google Safe Browse 15%
  PhishTank          10%
  AbuseIPDB           5%
  URLScan.io          5%

When an API has no key/fails its weight is redistributed to the ML model.
Final score is a true weighted average — always in 0-100 range.
"""
import concurrent.futures, socket, re, ssl, datetime, urllib.parse
from django.conf import settings


def _heuristic_analysis(url: str) -> dict:
    flags = []
    score = 0
    try:
        parsed   = urllib.parse.urlparse(url if '://' in url else 'http://'+url)
        hostname = (parsed.hostname or '').lower()
        scheme   = parsed.scheme.lower()
        path     = parsed.path.lower()
    except Exception:
        return {'flags': ['Invalid URL'], 'heuristic_score': 50, 'resolved_ip': None, 'hostname': ''}

    parts  = hostname.replace('www.','').split('.')
    root   = '.'.join(parts[-2:]) if len(parts)>=2 else hostname
    tld    = parts[-1] if len(parts)>1 else ''

    HIGH_RISK_TLDS = {'tk','ml','ga','cf','gq','pw','xyz','top','icu','click','vip','win','loan'}

    if scheme != 'https':
        score += 15; flags.append('⚠️  No HTTPS — connection is unencrypted')
    else:
        flags.append('✅  HTTPS enabled')

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 35; flags.append('🚨  Raw IP address used as hostname — strong phishing indicator')

    if len(url) > 100:
        score += 10; flags.append(f'⚠️  Long URL ({len(url)} chars) — common obfuscation tactic')

    if len(parts) > 4:
        score += 15; flags.append(f'⚠️  Deep subdomain nesting ({len(parts)-2} levels)')

    if '@' in url:
        score += 20; flags.append('🚨  @ symbol in URL — tricks browser into ignoring the domain part')

    if tld in HIGH_RISK_TLDS:
        score += 25; flags.append(f'🚨  High-risk TLD (.{tld}) — frequently used in phishing campaigns')

    if '-' in root and tld not in ('co','com','org','net','gov','edu'):
        score += 10; flags.append('⚠️  Hyphenated domain — often used to spoof legitimate brands')

    SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','rb.gy','cutt.ly'}
    if root in SHORTENERS:
        score += 20; flags.append('⚠️  URL shortener — real destination is hidden')

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
        flags.append(f'✅  Domain resolves → {resolved_ip}')
    except Exception:
        score += 25; flags.append('🚨  Domain does not resolve — likely fake or taken down')

    if scheme == 'https' and hostname and resolved_ip:
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
            conn.settimeout(3)
            conn.connect((hostname, 443))
            cert = conn.getpeercert()
            conn.close()
            exp  = datetime.datetime.strptime(cert.get('notAfter',''), '%b %d %H:%M:%S %Y %Z')
            days = (exp - datetime.datetime.utcnow()).days
            if days < 0:
                score += 25; flags.append('🚨  SSL certificate EXPIRED')
            elif days < 14:
                score += 10; flags.append(f'⚠️  SSL expires in {days} days')
            else:
                flags.append(f'✅  SSL valid for {days} more days')
        except ssl.SSLError:
            score += 15; flags.append('⚠️  SSL certificate error or self-signed')
        except Exception:
            pass

    return {
        'flags':           flags,
        'heuristic_score': min(100, score),
        'resolved_ip':     resolved_ip,
        'hostname':        hostname,
    }


def full_scan(url: str, ml_result: dict, include_ti: bool = True) -> dict:
    from threat_intel import virustotal, google_safebrowsing, phishtank, abuseipdb, urlscan_io

    heuristic = _heuristic_analysis(url)

    ti = {
        'virustotal':          {'available': False, 'risk_score': 0, 'error': 'Skipped'},
        'google_safebrowsing': {'available': False, 'risk_score': 0, 'error': 'Skipped'},
        'phishtank':           {'available': False, 'risk_score': 0, 'error': 'Skipped'},
        'abuseipdb':           {'available': False, 'risk_score': 0, 'error': 'Skipped'},
        'urlscan':             {'available': False, 'risk_score': 0, 'error': 'Skipped'},
    }

    if include_ti:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = {
                'virustotal':          ex.submit(virustotal.check,          url),
                'google_safebrowsing': ex.submit(google_safebrowsing.check, url),
                'phishtank':           ex.submit(phishtank.check,           url),
                'abuseipdb':           ex.submit(abuseipdb.check,           url),
                'urlscan':             ex.submit(urlscan_io.check,          url),
            }
            for name, fut in futures.items():
                try:    ti[name] = fut.result(timeout=35)
                except Exception as e: ti[name] = {'available': False, 'risk_score': 0, 'error': str(e)}

    # ── Weighted risk score ────────────────────────────────────────────────────
    WEIGHTS = getattr(settings, 'RISK_WEIGHTS', {
        'ml_model': 0.40, 'virustotal': 0.25,
        'google_safe_browsing': 0.15, 'phishtank': 0.10,
        'abuseipdb': 0.05, 'urlscan': 0.05,
    })

    ml_score = ml_result.get('ml_risk_score', 0)

    # Correct weighted average: unavailable APIs redistribute weight to ML
    effective_ml_weight = WEIGHTS['ml_model']
    api_weighted_sum    = 0.0

    api_map = {
        'virustotal':          (ti['virustotal'].get('risk_score', 0),          WEIGHTS['virustotal']),
        'google_safebrowsing': (ti['google_safebrowsing'].get('risk_score', 0), WEIGHTS['google_safe_browsing']),
        'phishtank':           (ti['phishtank'].get('risk_score', 0),           WEIGHTS['phishtank']),
        'abuseipdb':           (ti['abuseipdb'].get('risk_score', 0),           WEIGHTS['abuseipdb']),
        'urlscan':             (ti['urlscan'].get('risk_score', 0),             WEIGHTS['urlscan']),
    }

    for key, (score, weight) in api_map.items():
        if ti[key].get('available', False):
            api_weighted_sum    += score * weight
        else:
            effective_ml_weight += weight   # redistribute to ML

    final_risk_score = int(round(ml_score * effective_ml_weight + api_weighted_sum))
    final_risk_score = max(0, min(100, final_risk_score))

    # Heuristic bump: very suspicious URLs that ML underscored
    if heuristic['heuristic_score'] > 65 and final_risk_score < 45:
        final_risk_score = min(100, final_risk_score + (heuristic['heuristic_score'] - 65) // 4)

    # ── Threat level ──────────────────────────────────────────────────────────
    if   final_risk_score <= 20: level, emoji, rec = 'Safe',       '🟢', 'This URL appears safe. Standard precautions apply.'
    elif final_risk_score <= 40: level, emoji, rec = 'Low Risk',   '🔵', 'Exercise caution. Verify source before entering sensitive info.'
    elif final_risk_score <= 60: level, emoji, rec = 'Suspicious', '🟡', 'Do NOT enter credentials. Verify via official channels first.'
    elif final_risk_score <= 80: level, emoji, rec = 'High Risk',  '🔴', 'Likely malicious. Do NOT visit. Report to your IT team.'
    else:                         level, emoji, rec = 'Malicious',  '☠️', 'CONFIRMED MALICIOUS. Block immediately. Report to cybersecurity team.'

    return {
        'url':              url,
        'final_risk_score': final_risk_score,
        'threat_level':     level,
        'threat_emoji':     emoji,
        'recommendation':   rec,
        'ml_prediction':    ml_result,
        'heuristic':        heuristic,
        'threat_intel':     ti,
        'component_scores': {
            'ml_model':            ml_score,
            'virustotal':          api_map['virustotal'][0],
            'google_safe_browsing':api_map['google_safebrowsing'][0],
            'phishtank':           api_map['phishtank'][0],
            'abuseipdb':           api_map['abuseipdb'][0],
            'urlscan':             api_map['urlscan'][0],
            'heuristic':           heuristic['heuristic_score'],
        },
    }
