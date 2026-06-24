import requests
from django.conf import settings


def check(url: str) -> dict:
    """
    Check if URL is a known phishing site in PhishTank's database.
    """

    result = {
        'available': False,
        'in_database': False,
        'verified': False,
        'risk_score': 0,
        'phish_detail_url': None,
        'error': None,
    }

    try:
        api_key = getattr(settings, 'PHISHTANK_API_KEY', '')

        payload = {
            'url': url,
            'format': 'json'
        }

        if api_key:
            payload['app_key'] = api_key

        resp = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data=payload,
            timeout=10,
            headers={
                'User-Agent': 'CyberShield/1.0 (https://cybershield.local)'
            }
        )

        # Gracefully handle Cloudflare / blocked requests
        if resp.status_code != 200:
            result['error'] = 'PhishTank unavailable'
            return result

        data = resp.json()

        result['available'] = True

        results = data.get('results', {})

        result['in_database'] = results.get('in_database', False)
        result['verified'] = results.get('verified', False)
        result['phish_detail_url'] = results.get('phish_detail_url')

        if result['in_database'] and result['verified']:
            result['risk_score'] = 100
        elif result['in_database']:
            result['risk_score'] = 75

    except Exception as e:
        result['error'] = f'PhishTank check failed: {type(e).__name__}: {e}'

    return result