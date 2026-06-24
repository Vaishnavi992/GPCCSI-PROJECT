"""
Google Safe Browsing API v4
============================
Checks URLs against Google's constantly updated lists of:
- Social engineering (phishing & deceptive sites)
- Malware distribution
- Unwanted software
- Potentially harmful applications

Free tier: 10,000 requests/day.
Get API key: https://developers.google.com/safe-browsing/v4/get-started
"""
import requests
from django.conf import settings


def check(url: str) -> dict:
    """
    Check URL against Google Safe Browsing.

    Returns:
        {
          'available': bool,
          'is_safe': bool,
          'threat_types': list,
          'platform_types': list,
          'risk_score': 0-100,
          'error': str or None,
        }
    """
    result = {
        'available': False, 'is_safe': True,
        'threat_types': [], 'platform_types': [],
        'risk_score': 0, 'error': None,
    }

    api_key = getattr(settings, 'GOOGLE_SAFE_BROWSING_API_KEY', '')
    if not api_key:
        result['error'] = 'No API key — add GOOGLE_SAFE_BROWSING_API_KEY to .env'
        return result

    payload = {
        'client':     {'clientId': 'cybershield', 'clientVersion': '1.0'},
        'threatInfo': {
            'threatTypes':      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                                 'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED'],
            'platformTypes':    ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries':    [{'url': url}],
        },
    }

    try:
        resp = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
            json=payload, timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        result['available'] = True

        matches = data.get('matches', [])
        if matches:
            result['is_safe']       = False
            result['threat_types']  = list({m.get('threatType','')  for m in matches})
            result['platform_types']= list({m.get('platformType','') for m in matches})

            # Score: each threat type adds weight
            THREAT_WEIGHTS = {
                'MALWARE': 90,
                'SOCIAL_ENGINEERING': 85,
                'UNWANTED_SOFTWARE': 60,
                'POTENTIALLY_HARMFUL_APPLICATION': 70,
            }
            max_score = max(
                THREAT_WEIGHTS.get(t, 50) for t in result['threat_types']
            ) if result['threat_types'] else 50
            result['risk_score'] = max_score

    except Exception as e:
        result['error'] = f'Google Safe Browsing failed: {type(e).__name__}: {e}'

    return result
