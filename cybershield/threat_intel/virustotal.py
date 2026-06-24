"""
VirusTotal Integration
======================
Scans a URL against 90+ antivirus and security engines.
Free tier: 4 requests/minute, 500/day.
Get API key: https://www.virustotal.com/gui/join-us
"""
import time, base64, json, requests
from django.conf import settings


def check(url: str) -> dict:
    """
    Submit URL to VirusTotal and return aggregated results.

    Returns:
        {
          'available': True/False,
          'malicious': int,
          'suspicious': int,
          'harmless': int,
          'undetected': int,
          'total_engines': int,
          'permalink': str,
          'risk_score': 0-100,
          'error': str or None,
        }
    """
    result = {
        'available': False, 'malicious': 0, 'suspicious': 0,
        'harmless': 0, 'undetected': 0, 'total_engines': 0,
        'permalink': None, 'risk_score': 0, 'error': None,
    }

    api_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
    if not api_key:
        result['error'] = 'No API key configured — add VIRUSTOTAL_API_KEY to .env'
        return result

    headers = {'x-apikey': api_key, 'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        # Step 1: Submit URL for scanning
        resp = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            data={'url': url},
            headers=headers,
            timeout=15
        )
        resp.raise_for_status()
        scan_id = resp.json()['data']['id']

        # Step 2: Wait briefly and retrieve results
        time.sleep(2)
        analysis_resp = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{scan_id}',
            headers={'x-apikey': api_key},
            timeout=15
        )
        analysis_resp.raise_for_status()
        stats = analysis_resp.json()['data']['attributes']['stats']

        result['available']    = True
        result['malicious']    = stats.get('malicious',  0)
        result['suspicious']   = stats.get('suspicious', 0)
        result['harmless']     = stats.get('harmless',   0)
        result['undetected']   = stats.get('undetected', 0)
        result['total_engines'] = sum(stats.values())

        # Permalink to full VirusTotal report
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        result['permalink'] = f'https://www.virustotal.com/gui/url/{url_id}'

        # Risk score: malicious engines weighted 3x, suspicious 1x
        if result['total_engines'] > 0:
            weighted = (result['malicious'] * 3 + result['suspicious']) / result['total_engines']
            result['risk_score'] = min(100, int(weighted * 100))

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 429:
            result['error'] = 'VirusTotal rate limit reached (4 req/min on free tier)'
        else:
            result['error'] = f'VirusTotal API error: {e}'
    except Exception as e:
        result['error'] = f'VirusTotal check failed: {type(e).__name__}: {e}'

    return result
