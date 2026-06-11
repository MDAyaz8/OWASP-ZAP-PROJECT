# app.py
from zap_helper import connect_zap, get_intercepted_requests, run_fuzzing, run_auth_testing, scan_api_endpoints, run_spider, run_passive_scan, run_active_scan, generate_report
from flask import Flask, render_template, redirect, url_for, send_file

app = Flask(__name__)

scan_data = {
    'urls': [],
    'alerts': [],
    'spider_done': False,
    'passive_done': False,
    'active_done': False,
    'proxy_done': False,        # new
    'fuzz_done': False,
    'auth_done': False,  # new
    'api_done': False,  # new
    'proxy_requests': [],       # new
    'fuzz_results': [],         # new
    'auth_results': [],         # new
    'api_results': [],          # new
    'active_alerts': {
        'all': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
}


@app.route('/')
def home():
    zap, version, status = connect_zap()
    return render_template('index.html',
                           zap_status=status,
                           zap_version=version,
                           scan_data=scan_data
                           )


@app.route('/spider')
def spider():
    zap, version, status = connect_zap()
    if zap:
        urls = run_spider(zap)
        scan_data['urls'] = urls
        scan_data['spider_done'] = True
    return redirect(url_for('home'))


@app.route('/passive')
def passive():
    zap, version, status = connect_zap()
    if zap:
        alerts = run_passive_scan(zap)
        scan_data['alerts'] = alerts
        scan_data['passive_done'] = True
    return redirect(url_for('home'))


@app.route('/active')
def active():
    zap, version, status = connect_zap()
    if zap:
        results = run_active_scan(zap)
        scan_data['active_alerts'] = results
        scan_data['active_done'] = True
    return redirect(url_for('home'))


@app.route('/report')
def report():
    json_path, html_path = generate_report(scan_data)
    return send_file(html_path, as_attachment=True)


@app.route('/proxy')
def proxy():
    zap, version, status = connect_zap()
    if zap:
        requests_list = get_intercepted_requests(zap)
        scan_data['proxy_requests'] = requests_list
        scan_data['proxy_done'] = True
    return redirect(url_for('home'))


@app.route('/fuzz')
def fuzz():
    zap, version, status = connect_zap()
    if zap:
        results = run_fuzzing(zap)
        scan_data['fuzz_results'] = results
        scan_data['fuzz_done'] = True
    return redirect(url_for('home'))


@app.route('/auth')
def auth():
    zap, version, status = connect_zap()
    if zap:
        results = run_auth_testing(zap)
        scan_data['auth_results'] = results
        scan_data['auth_done'] = True
    return redirect(url_for('home'))


@app.route('/api-scan')
def api_scan():
    zap, version, status = connect_zap()
    if zap:
        results = scan_api_endpoints(zap)
        scan_data['api_results'] = results
        scan_data['api_done'] = True
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
