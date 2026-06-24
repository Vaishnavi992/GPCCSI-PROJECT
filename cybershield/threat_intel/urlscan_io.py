"""
URLScan.io Integration
=======================
URLScan.io is a sandbox for scanning URLs — it takes a screenshot,
checks links, examines DOM, and flags malicious content.

Free tier: 100 scans/hour, 5,000/day.
Get API key: https://urlscan.io/user/signup
"""

import time
import requests
from django.conf import settings


def check(url: str) -> dict:
    """
    Submit URL to URLScan.io and retrieve results.
    """

    result = {
        'available': False,
        'is_malicious': False,
        'score': 0,
        'tags': [],
        'screenshot_url': None,
        'result_url': None,
        'risk_score': 0,
        'error': None,
    }

    api_key = getattr(settings, 'URLSCAN_API_KEY', '')

    if not api_key:
        result['error'] = 'No API key — add URLSCAN_API_KEY to .env'
        return result

    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json',
    }

    try:
        # Submit URL for scan
        submit_resp = requests.post(
            'https://urlscan.io/api/v1/scan/',
            json={
                'url': url,
                'visibility': 'public'
            },
            headers=headers,
            timeout=20
        )

        submit_resp.raise_for_status()

        scan_data = submit_resp.json()

        result_api_url = scan_data.get('api')
        uuid = scan_data.get('uuid')

        if not result_api_url:
            result['error'] = 'URLScan did not return a result URL'
            return result

        # Wait for report generation
        data = None

        for _ in range(10):  # ~50 sec max
            result_resp = requests.get(
                result_api_url,
                headers=headers,
                timeout=20
            )

            if result_resp.status_code == 200:
                data = result_resp.json()
                break

            elif result_resp.status_code == 404:
                time.sleep(5)
                continue

            else:
                result_resp.raise_for_status()

        if data is None:
            result['available'] = True
            result['error'] = 'Scan submitted, report still processing'
            result['result_url'] = f'https://urlscan.io/result/{uuid}/'
            return result

        verdicts = data.get('verdicts', {})
        overall = verdicts.get('overall', {})

        result['available'] = True
        result['is_malicious'] = overall.get('malicious', False)
        result['score'] = overall.get('score', 0)
        result['tags'] = overall.get('tags', [])
        result['result_url'] = f'https://urlscan.io/result/{uuid}/'
        result['screenshot_url'] = data.get('task', {}).get('screenshotURL')
        result['risk_score'] = max(
            0,
            min(100, int(result['score']))
        )

    except requests.exceptions.HTTPError as e:

        if e.response is not None:
            print("=" * 60)
            print("URLSCAN STATUS:", e.response.status_code)
            print("URLSCAN RESPONSE:", e.response.text)
            print("=" * 60)

        result['error'] = f'URLScan API error: {e}'

    except Exception as e:
        result['error'] = (
            f'URLScan check failed: '
            f'{type(e).__name__}: {e}'
        )

    return result