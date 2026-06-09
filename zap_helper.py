# zap_helper.py
import json
from datetime import datetime
import time

try:
    from zapv2 import ZAPv2  # type: ignore[import]
except ImportError:
    ZAPv2 = None

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
    scan_id = zap.ascan.scan(TARGET, apikey=ZAP_API_KEY)

    while True:
        progress = int(zap.ascan.status(scan_id))
        print(f'Active scan progress: {progress}%')
        if progress >= 100:
            break
        time.sleep(5)

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


def generate_report(scan_data):
    report = {
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': TARGET,
        'spider_urls': scan_data.get('urls', []),
        'passive_alerts': len(scan_data.get('alerts', [])),
        'active_summary': {
            'high':   len(scan_data.get('active_alerts', {}).get('high', [])),
            'medium': len(scan_data.get('active_alerts', {}).get('medium', [])),
            'low':    len(scan_data.get('active_alerts', {}).get('low', [])),
            'info':   len(scan_data.get('active_alerts', {}).get('info', []))
        },
        'all_alerts': scan_data.get('active_alerts', {}).get('all', [])
    }

    # Save JSON file
    json_path = 'reports/scan_report.json'
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Save HTML file
    html_path = 'reports/scan_report.html'
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZAP Scan Report</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            h1 {{ color: #333; }}
            .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
            .box {{ padding: 20px; border-radius: 8px; text-align: center; flex: 1; }}
            .high   {{ background: #ffe0e0; border: 2px solid red; }}
            .medium {{ background: #fff3cd; border: 2px solid orange; }}
            .low    {{ background: #e0f7e0; border: 2px solid green; }}
            .info   {{ background: #e0f0ff; border: 2px solid blue; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #333; color: white; padding: 10px; text-align: left; }}
            td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
            .row-High          {{ background: #ffe0e0; }}
            .row-Medium        {{ background: #fff3cd; }}
            .row-Low           {{ background: #e0f7e0; }}
            .row-Informational {{ background: #e0f0ff; }}
        </style>
    </head>
    <body>
        <h1>OWASP ZAP Security Scan Report</h1>
        <p><strong>Date:</strong> {report['date']}</p>
        <p><strong>Target:</strong> {report['target']}</p>
        <p><strong>URLs Discovered:</strong> {len(report['spider_urls'])}</p>
        <p><strong>Passive Alerts:</strong> {report['passive_alerts']}</p>

        <h2>Active Scan Summary</h2>
        <div class="summary">
            <div class="box high">High<br><strong>{report['active_summary']['high']}</strong></div>
            <div class="box medium">Medium<br><strong>{report['active_summary']['medium']}</strong></div>
            <div class="box low">Low<br><strong>{report['active_summary']['low']}</strong></div>
            <div class="box info">Info<br><strong>{report['active_summary']['info']}</strong></div>
        </div>

        <h2>All Alerts</h2>
        <table>
            <tr>
                <th>Risk</th>
                <th>Alert</th>
                <th>URL</th>
                <th>Solution</th>
            </tr>
            {''.join(f"""
            <tr class="row-{a.get('risk', 'Low')}">
                <td>{a.get('risk', '')}</td>
                <td>{a.get('alert', '')}</td>
                <td>{a.get('url', '')[:50]}</td>
                <td>{a.get('solution', '')[:80]}</td>
            </tr>""" for a in report['all_alerts'])}
        </table>
    </body>
    </html>
    """
    with open(html_path, 'w') as f:
        f.write(html)

    return json_path, html_path
