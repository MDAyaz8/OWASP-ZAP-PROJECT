# zap_helper.py
import json
from datetime import datetime
from zapv2 import ZAPv2
import time
import requests as req

ZAP_PROXY = 'http://127.0.0.1:8080'
ZAP_API_KEY = 'ndfro34675l4pdnbs3dfj13i1p'
TARGET = 'http://127.0.0.1:5001'


def connect_zap():
    try:
        zap = ZAPv2(
            apikey=ZAP_API_KEY,
            proxies={'http': ZAP_PROXY, 'https': ZAP_PROXY}
        )
        version = zap.core.version
        return zap, version, 'Connected ✅'
    except Exception as e:
        return None, 'Unknown', f'Error ❌: {str(e)}'


def run_spider(zap):
    print(f'Spider starting on {TARGET}...')
    scan_id = zap.spider.scan(TARGET, apikey=ZAP_API_KEY)

    # Spider complete అయ్యే వరకు wait చెయ్యి
    while True:
        progress = int(zap.spider.status(scan_id))
        print(f'Spider progress: {progress}%')
        if progress >= 100:
            break
        time.sleep(2)

    urls = zap.spider.results(scan_id)
    print(f'Spider done! {len(urls)} URLs found')
    return urls


def run_passive_scan(zap):
    print('Passive scan running...')

    # Passive scan queue empty అయ్యే వరకు wait
    while True:
        records = int(zap.pscan.records_to_scan)
        print(f'Records left to scan: {records}')
        if records == 0:
            break
        time.sleep(2)

    alerts = zap.core.alerts(baseurl=TARGET)
    print(f'Passive scan done! {len(alerts)} alerts found')
    return alerts


def run_active_scan(zap):
    print(f'Active scan starting on {TARGET}...')

    # First access the target so ZAP knows it
    zap.urlopen(TARGET)
    time.sleep(2)

    # Start active scan
    scan_id = zap.ascan.scan(TARGET, apikey=ZAP_API_KEY)
    print(f'Scan ID: {scan_id}')

    time.sleep(3)

    while True:
        try:
            status = zap.ascan.status(scan_id)
            # Fix — handle 'does_not_exist' error
            if str(status).isdigit():
                progress = int(status)
            else:
                print(f'Scan status: {status} — retrying...')
                time.sleep(3)
                continue

            print(f'Active scan progress: {progress}%')
            if progress >= 100:
                break
            time.sleep(5)

        except Exception as e:
            print(f'Error: {e} — retrying...')
            time.sleep(3)
            continue

    alerts = zap.core.alerts(baseurl=TARGET)

    high = [a for a in alerts if a['risk'] == 'High']
    medium = [a for a in alerts if a['risk'] == 'Medium']
    low = [a for a in alerts if a['risk'] == 'Low']
    info = [a for a in alerts if a['risk'] == 'Informational']

    return {
        'all': alerts,
        'high': high,
        'medium': medium,
        'low': low,
        'info': info
    }


def generate_report(scan_data, zap=None):
    from datetime import datetime
    import json

    # Collect all data
    active_alerts = scan_data.get('active_alerts', {})
    all_alerts = active_alerts.get('all', [])
    high = active_alerts.get('high', [])
    medium = active_alerts.get('medium', [])
    low = active_alerts.get('low', [])
    info = active_alerts.get('info', [])

    report = {
        'date':            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target':          TARGET,
        'spider_urls':     scan_data.get('urls', []),
        'passive_alerts':  len(scan_data.get('alerts', [])),
        'active_summary': {
            'high':   len(high),
            'medium': len(medium),
            'low':    len(low),
            'info':   len(info)
        },
        'all_alerts':      all_alerts,
        'fuzz_results':    scan_data.get('fuzz_results', []),
        'auth_results':    scan_data.get('auth_results', []),
        'api_results':     scan_data.get('api_results', []),
        'proxy_requests':  scan_data.get('proxy_requests', [])
    }

    # Save JSON
    json_path = 'reports/scan_report.json'
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Save XML if ZAP connected
    if zap:
        try:
            xml_data = zap.core.xmlreport(apikey=ZAP_API_KEY)
            with open('reports/scan_report.xml', 'w',
                      encoding='utf-8') as f:
                f.write(xml_data)
            print('XML report saved!')
        except Exception as e:
            print(f'XML error: {e}')

    # Generate Advanced HTML Report
    html_path = 'reports/scan_report.html'
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>OWASP ZAP Advanced Security Report</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: Arial, sans-serif;
            background: #f0f2f5;
            color: #333;
        }}
        .header {{
            background: #1a1a2e;
            color: white;
            padding: 30px 40px;
        }}
        .header h1 {{
            font-size: 1.8rem;
            color: #00d4ff;
        }}
        .header p {{
            color: rgba(255,255,255,0.6);
            margin-top: 5px;
            font-size: 13px;
        }}
        .container {{
            max-width: 1100px;
            margin: 30px auto;
            padding: 0 20px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4,1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .kpi-val {{
            font-size: 2.2rem;
            font-weight: 900;
            line-height: 1;
        }}
        .kpi-lbl {{
            font-size: 12px;
            color: #666;
            margin-top: 6px;
        }}
        .kpi.high   .kpi-val {{ color: #dc3545; }}
        .kpi.medium .kpi-val {{ color: #fd7e14; }}
        .kpi.low    .kpi-val {{ color: #28a745; }}
        .kpi.info   .kpi-val {{ color: #007bff; }}
        .section {{
            background: white;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        .section h2 {{
            font-size: 1.1rem;
            color: #1a1a2e;
            border-bottom: 2px solid #f0f2f5;
            padding-bottom: 12px;
            margin-bottom: 16px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }}
        th {{
            background: #1a1a2e;
            color: white;
            padding: 10px;
            text-align: left;
        }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
        .row-High          {{ background: #ffe0e0; }}
        .row-Medium        {{ background: #fff3cd; }}
        .row-Low           {{ background: #e0f7e0; }}
        .row-Informational {{ background: #e0f0ff; }}
        .row-exposed {{ background: #fff3cd; }}
        .row-protected {{ background: #e0f7e0; }}
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge-high   {{ background: #ffe0e0; color: #dc3545; }}
        .badge-medium {{ background: #fff3cd; color: #fd7e14; }}
        .badge-low    {{ background: #e0f7e0; color: #28a745; }}
        .badge-info   {{ background: #e0f0ff; color: #007bff; }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 12px;
        }}
    </style>
</head>
<body>

<div class="header">
    <h1>OWASP ZAP Advanced Security Report</h1>
    <p>Generated: {report['date']} |
       Target: {report['target']} |
       URLs Found: {len(report['spider_urls'])}</p>
</div>

<div class="container">

    <!-- KPI Summary -->
    <div class="kpi-grid">
        <div class="kpi high">
            <div class="kpi-val">{report['active_summary']['high']}</div>
            <div class="kpi-lbl">High Risk</div>
        </div>
        <div class="kpi medium">
            <div class="kpi-val">{report['active_summary']['medium']}</div>
            <div class="kpi-lbl">Medium Risk</div>
        </div>
        <div class="kpi low">
            <div class="kpi-val">{report['active_summary']['low']}</div>
            <div class="kpi-lbl">Low Risk</div>
        </div>
        <div class="kpi info">
            <div class="kpi-val">{report['active_summary']['info']}</div>
            <div class="kpi-lbl">Informational</div>
        </div>
    </div>

    <!-- Active Scan Alerts -->
    <div class="section">
        <h2>⚡ Active Scan Alerts
            ({len(report['all_alerts'])} total)
        </h2>
        <table>
            <tr>
                <th>Risk</th>
                <th>Alert</th>
                <th>URL</th>
                <th>Solution</th>
            </tr>
            {''.join(f"""
            <tr class="row-{a.get('risk', 'Low')}">
                <td>
                    <span class="badge badge-{
        a.get('risk', 'Low').lower()
    }">{a.get('risk', '')}</span>
                </td>
                <td>{a.get('alert', '')}</td>
                <td>{a.get('url', '')[:50]}</td>
                <td>{a.get('solution', '')[:60]}</td>
            </tr>""" for a in report['all_alerts'])}
        </table>
    </div>

    <!-- Fuzzing Results -->
    <div class="section">
        <h2>🎯 Fuzzing Results
            ({len(report['fuzz_results'])} tests)
        </h2>
        <table>
            <tr>
                <th>Endpoint</th>
                <th>Type</th>
                <th>Payload</th>
                <th>Status</th>
                <th>Result</th>
            </tr>
            {''.join(f"""
            <tr class="{'row-High' if 'REFLECTED'
                        in r.get('result', '')
                        else 'row-Low'}">
                <td>{r.get('endpoint', '')}</td>
                <td>{r.get('type', '')}</td>
                <td>{r.get('payload', '')[:35]}</td>
                <td>{r.get('status_code', '')}</td>
                <td><b>{r.get('result', '')}</b></td>
            </tr>""" for r in report['fuzz_results'])}
        </table>
    </div>

    <!-- Auth Testing Results -->
    <div class="section">
        <h2>🔐 Authentication Testing
            ({len(report['auth_results'])} tests)
        </h2>
        <table>
            <tr>
                <th>Username</th>
                <th>Password</th>
                <th>Expected</th>
                <th>Actual</th>
                <th>Result</th>
            </tr>
            {''.join(f"""
            <tr class="{'row-High' if 'UNEXPECTED'
                            in r.get('result', '')
                            else 'row-Low'}">
                <td>{r.get('username', '')}</td>
                <td>{r.get('password', '')}</td>
                <td>{r.get('expected', '')}</td>
                <td>{r.get('actual', '')}</td>
                <td><b>{r.get('result', '')}</b></td>
            </tr>""" for r in report['auth_results'])}
        </table>
    </div>

    <!-- API Results -->
    <div class="section">
        <h2>🔌 API Endpoints
            ({len(report['api_results'])} tested)
        </h2>
        <table>
            <tr>
                <th>Endpoint</th>
                <th>Method</th>
                <th>Status</th>
                <th>Response</th>
                <th>Risk</th>
            </tr>
            {''.join(f"""
            <tr class="{'row-exposed' if 'EXPOSED'
                                in r.get('accessible', '')
                                else 'row-protected'}">
                <td>{r.get('url', '')}</td>
                <td>{r.get('method', '')}</td>
                <td>{r.get('status_code', '')}</td>
                <td>{r.get('response', '')[:50]}</td>
                <td><b>{r.get('accessible', '')}</b></td>
            </tr>""" for r in report['api_results'])}
        </table>
    </div>

    <!-- Spider URLs -->
    <div class="section">
        <h2>🕷️ Discovered URLs
            ({len(report['spider_urls'])} URLs)
        </h2>
        <table>
            <tr><th>URL</th></tr>
            {''.join(f"<tr><td>{url}</td></tr>"
                                    for url in report['spider_urls'])}
        </table>
    </div>

</div>

<div class="footer">
    OWASP ZAP Security Report |
    Generated: {report['date']} |
    Target: {report['target']}
</div>

</body>
</html>"""

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f'Reports saved to reports/ folder')
    return json_path, html_path


def get_intercepted_requests(zap):
    try:
        messages = zap.core.messages(baseurl=TARGET)
        requests_list = []
        for msg in messages:
            # requestHeader నుండి method తీసుకో
            req_header = msg.get('requestHeader', '')
            resp_header = msg.get('responseHeader', '')

            # First line: "GET http://127.0.0.1:5001/ HTTP/1.1"
            method = 'GET'
            url = TARGET
            status_code = 'N/A'

            if req_header:
                first_line = req_header.split('\r\n')[0]
                parts = first_line.strip().split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    url = parts[1]

            # Response header నుండి status code తీసుకో
            if resp_header:
                resp_first = resp_header.split('\r\n')[0]
                resp_parts = resp_first.strip().split(' ')
                if len(resp_parts) >= 2:
                    status_code = resp_parts[1]

            requests_list.append({
                'method': method,
                'url': url[:60],
                'status_code': status_code
            })

        print(f'Intercepted {len(requests_list)} requests')
        return requests_list

    except Exception as e:
        print(f'Proxy error: {e}')
        return []


def run_fuzzing(zap):
    # Test endpoints with crafted payloads
    fuzz_results = []

    # Payloads to test
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1' AND SLEEP(5)--",
        "' UNION SELECT NULL--"
    ]

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg/onload=alert(1)>"
    ]

    path_traversal = [
        "../../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "%2e%2e%2fetc/passwd"
    ]

    # Test search endpoint with SQL injection
    print('Fuzzing search endpoint...')
    for payload in sqli_payloads:
        try:
            response = req.get(
                f'{TARGET}/search',
                params={'q': payload},
                timeout=5
            )
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'SQL Injection',
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'result': 'Responded' if response.status_code == 200
                          else 'Blocked'
            })
        except Exception as e:
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'SQL Injection',
                'payload': payload,
                'status_code': 'Error',
                'response_length': 0,
                'result': str(e)
            })

    # Test search endpoint with XSS
    print('Fuzzing XSS payloads...')
    for payload in xss_payloads:
        try:
            response = req.get(
                f'{TARGET}/search',
                params={'q': payload},
                timeout=5
            )
            # Check if payload reflected in response
            reflected = payload in response.text
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'XSS',
                'payload': payload[:40],
                'status_code': response.status_code,
                'response_length': len(response.text),
                'result': '⚠️ REFLECTED' if reflected else 'Not Reflected'
            })
        except Exception as e:
            fuzz_results.append({
                'endpoint': '/search',
                'type': 'XSS',
                'payload': payload[:40],
                'status_code': 'Error',
                'response_length': 0,
                'result': str(e)
            })

    # Test login with path traversal
    print('Fuzzing path traversal...')
    for payload in path_traversal:
        try:
            response = req.post(
                f'{TARGET}/login',
                data={'username': payload, 'password': 'test'},
                timeout=5
            )
            fuzz_results.append({
                'endpoint': '/login',
                'type': 'Path Traversal',
                'payload': payload,
                'status_code': response.status_code,
                'response_length': len(response.text),
                'result': 'Responded'
            })
        except Exception as e:
            fuzz_results.append({
                'endpoint': '/login',
                'type': 'Path Traversal',
                'payload': payload,
                'status_code': 'Error',
                'response_length': 0,
                'result': str(e)
            })

    print(f'Fuzzing done! {len(fuzz_results)} tests run')
    return fuzz_results


def run_auth_testing(zap):
    auth_results = []

    # Test credentials
    test_credentials = [
        {'username': 'admin',  'password': 'admin123',   'expected': 'success'},
        {'username': 'user',   'password': 'password123', 'expected': 'success'},
        {'username': 'admin',  'password': 'wrongpass',  'expected': 'fail'},
        {'username': 'hacker', 'password': 'hacker123',  'expected': 'fail'},
        {'username': 'admin',  'password': '',           'expected': 'fail'},
        {'username': '',       'password': 'admin123',   'expected': 'fail'},
        {'username': 'admin',  'password': 'admin',      'expected': 'fail'},
        {'username': "' OR '1'='1", 'password': 'any',  'expected': 'fail'},
    ]

    import requests as req
    for cred in test_credentials:
        try:
            response = req.post(
                f'{TARGET}/login',
                data={
                    'username': cred['username'],
                    'password': cred['password']
                },
                timeout=5
            )
            # Check response for success/failure
            if 'SUCCESS' in response.text:
                actual = 'success'
            else:
                actual = 'fail'

            # Check if result matches expected
            if actual == cred['expected']:
                result = '✅ Expected'
            else:
                result = '⚠️ UNEXPECTED'

            auth_results.append({
                'username': cred['username'][:20],
                'password': cred['password'][:15],
                'expected': cred['expected'],
                'actual':   actual,
                'status':   response.status_code,
                'result':   result
            })
            print(f"Auth test: {cred['username']} "
                  f"— {actual} — {result}")

        except Exception as e:
            auth_results.append({
                'username': cred['username'][:20],
                'password': cred['password'][:15],
                'expected': cred['expected'],
                'actual':   'error',
                'status':   'Error',
                'result':   str(e)[:30]
            })

    print(f'Auth testing done! {len(auth_results)} tests')
    return auth_results


def scan_api_endpoints(zap):
    api_results = []
    import requests as req

    # API endpoints to test
    endpoints = [
        {'url': f'{TARGET}/api/users',       'method': 'GET'},
        {'url': f'{TARGET}/api/user/admin',  'method': 'GET'},
        {'url': f'{TARGET}/api/user/test',   'method': 'GET'},
        {'url': f'{TARGET}/api/user/hacker', 'method': 'GET'},
        {'url': f'{TARGET}/api/status',      'method': 'GET'},
    ]

    for ep in endpoints:
        try:
            response = req.get(ep['url'], timeout=5)

            # Try to parse JSON
            try:
                json_data = response.json()
                data_preview = str(json_data)[:60]
            except:
                data_preview = response.text[:60]

            api_results.append({
                'url':          ep['url'].replace(TARGET, ''),
                'method':       ep['method'],
                'status_code':  response.status_code,
                'response':     data_preview,
                'accessible':   '⚠️ EXPOSED' if response.status_code == 200
                                else '✅ Protected'
            })
            print(f"API test: {ep['url']} "
                  f"— {response.status_code}")

        except Exception as e:
            api_results.append({
                'url':         ep['url'].replace(TARGET, ''),
                'method':      ep['method'],
                'status_code': 'Error',
                'response':    str(e)[:40],
                'accessible':  '❌ Error'
            })

    print(f'API scan done! {len(api_results)} endpoints tested')
    return api_results
