# app.py
from zap_helper import connect_zap, run_spider, run_passive_scan, run_active_scan, generate_report
from flask import Flask, render_template, redirect, url_for, send_file

app = Flask(__name__)

# Global గా results store చేయడానికి
scan_data = {
    'urls': [],
    'alerts': [],
    'spider_done': False,
    'passive_done': False,
    'active_done': False
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


if __name__ == '__main__':
    app.run(debug=True, port=5000)
