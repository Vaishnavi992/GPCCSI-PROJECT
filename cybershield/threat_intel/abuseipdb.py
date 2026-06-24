"""
AbuseIPDB Integration
======================
Checks if the IP address that a URL resolves to has been reported
for malicious activity (brute force, DDoS, phishing hosting, etc.)

Free tier: 1,000 checks/day.
Get API key: https://www.abuseipdb.com/register
"""
import socket, requests
from django.conf import settings


def _resolve_ip(url: str) -> str | None:
    """Extract hostname from URL and resolve to IP."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if '://' in url else 'http://' + url)
        hostname = parsed.hostname or ''
        if hostname:
            return socket.gethostbyname(hostname)
    except Exception:
        pass
    return None


def check(url: str) -> dict:
    """
    Check the IP address of a URL's host against AbuseIPDB.

    Returns:
        {
          'available': bool,
          'ip_address': str,
          'is_public': bool,
          'abuse_confidence': 0-100,
          'total_reports': int,
          'country_code': str,
          'isp': str,
          'risk_score': 0-100,
          'error': str or None,
        }
    """
    result = {
        'available': False, 'ip_address': None, 'is_public': True,
        'abuse_confidence': 0, 'total_reports': 0,
        'country_code': '', 'isp': '',
        'risk_score': 0, 'error': None,
    }

    api_key = getattr(settings, 'ABUSEIPDB_API_KEY', '')
    if not api_key:
        result['error'] = 'No API key — add ABUSEIPDB_API_KEY to .env'
        return result

    ip = _resolve_ip(url)
    if not ip:
        result['error'] = 'Could not resolve hostname to IP'
        return result

    result['ip_address'] = ip

    try:
        resp = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': False},
            headers={'Key': api_key, 'Accept': 'application/json'},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json().get('data', {})

        result['available']        = True
        result['is_public']        = data.get('isPublic', True)
        result['abuse_confidence'] = data.get('abuseConfidenceScore', 0)
        result['total_reports']    = data.get('totalReports', 0)
        result['country_code']     = data.get('countryCode', '')
        result['isp']              = data.get('isp', '')
        result['risk_score']       = result['abuse_confidence']

    except Exception as e:
        result['error'] = f'AbuseIPDB check failed: {type(e).__name__}: {e}'

    return result
