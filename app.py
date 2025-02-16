from flask import Flask, render_template, request, jsonify, send_file, session
import sqlite3,warnings,pickle
from flask_socketio import SocketIO,emit
from cyber_sentinel.crawler import Crawler
from cyber_sentinel.attacks import *
from cyber_sentinel.utils import dict_iterate, get_url_host, validate_url
from cyber_sentinel.client import Client
from cyber_sentinel.logger import Log
from cyber_sentinel.app_detect import app_detect
from datetime import datetime, timedelta
from timeit import default_timer as timer
import threading,os,json,time,random
from collections import defaultdict
import ipaddress
from functools import wraps
from flask import g
from flask import jsonify
import subprocess
import pdfkit
import tempfile
from dataclasses import dataclass
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor
from itertools import chain

warnings.filterwarnings('ignore')
from keras.models import load_model
# from feature import 
from feature import FeatureExtraction
model = load_model('model/model.h5')

file = open("model/model.pkl","rb")
gbc = pickle.load(file)
file.close()


connection = sqlite3.connect('user_data.db')
cursor = connection.cursor()

command = """CREATE TABLE IF NOT EXISTS user(name TEXT, password TEXT, mobile TEXT, email TEXT)"""
cursor.execute(command)

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'secret!'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
socketio = SocketIO(app)

# Add this after app initialization
app.app_context().push()

attacks = {
    'all_attacks': all_attacks,
    'xss': xss_attack,
    'hpp': hpp_attack,
    'sql': sql_error_attack,
    'csrf': csrf_attack,
    'crlf': crlf_attack,
    'lfi': lfi_attack,
    'directory_listing': directory_listing_attack,
    'breach': breach_attack,
    'clickjack': clickjack_attack,
    'cookiescan': cookiescan_attack
}

scan_running = False
current_scan_info = {
    'url': '',
    'host': '',
    'date': None,
    'scan_time': '',
    'detected_apps': {}
}
detected_vulns = []
vulns_info = {}
scan_counter = {'all': 0, 'vuln': 0, 'warn': 0}
scanned_urls = {}

# Update the cleanup_scan function
def cleanup_scan():
    global scan_running, current_scan_info, detected_vulns, scan_counter, scanned_urls
    scan_running = False
    
    try:
        # Generate report with current results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"scan_report_{timestamp}.html"
        
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir)
        
        report_path = os.path.join(reports_dir, report_filename)
        
        with app.app_context():
            report_html = render_template('report.html',
                                        info=current_scan_info,
                                        vulns=detected_vulns,
                                        vulns_info=vulns_info,
                                        counter=scan_counter,
                                        urls=scanned_urls)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report_html)
            
            print(f"Report generated: {report_path}")  # Debug print
            return report_filename
            
    except Exception as e:
        print(f"Error generating report: {e}")
        return None

# Update the run_scan_live function
def run_scan_live(target_url, choice, scan_all_pages):
    global scan_running, current_scan_info, detected_vulns, vulns_info, scan_counter, scanned_urls
    
    if scan_running:
        return
        
    scan_running = True
    start_time = time.time()
    date_now = datetime.today()
    
    try:
        # Initialize scan information
        current_scan_info = {
            'url': target_url,
            'host': get_url_host(target_url),
            'date': date_now,
            'scan_time': '',
            'detected_apps': {}
        }
        detected_vulns = []
        scan_counter = {'all': 0, 'vuln': 0, 'warn': 0}
        scanned_urls = {}

        target_url = validate_url(target_url)
        client = Client()
        log = Log()

        # Detect applications
        apps = app_detect(target_url, client)
        
        if apps:
            socketio.emit('log', {'log': 'Detected Technologies:'})
            for app, app_types in dict_iterate(apps):
                for app_type in app_types:
                    current_scan_info['detected_apps'].setdefault(app_type, []).append(app)
                app_types_string = ", ".join(app_types)
                socketio.emit('log', {'log': f'\t{app_types_string} - {app}'})

        if not scan_running:  # Check if stopped
            return cleanup_scan()

        # Get pages to scan
        if scan_all_pages:
            all_pages = Crawler(target_url, client, additional_pages=[])
        else:
            page = client.get(target_url)
            all_pages = [page]

        # Perform scanning
        selected_attack_function = attacks.get(choice)
        if selected_attack_function:
            for page in all_pages:
                if not scan_running:  # Check if stopped
                    return cleanup_scan()
                    
                socketio.emit('log', {'log': f'Checking page: [{page.status_code}] {page.url}'})
                scanned_urls[page.url] = 'green'
                
                for atk in selected_attack_function():
                    if not scan_running:  # Check if stopped
                        return cleanup_scan()
                        
                    socketio.emit('log', {'log': f'Running {atk.__name__} on {page.url}'})
                    try:
                        result = atk(page, client, log)
                        if result:
                            detected_vulns.extend(result)
                            scan_counter['all'] += len(result)
                            scan_counter['vuln'] += sum(1 for v in result if v.severity == 'high')
                            scan_counter['warn'] += sum(1 for v in result if v.severity == 'medium')
                    except Exception as e:
                        socketio.emit('log', {'log': f'Error in attack {atk.__name__}: {str(e)}'})
        else:
            socketio.emit('log', {'log': 'Invalid attack choice'})
            return cleanup_scan()

    except Exception as e:
        socketio.emit('log', {'log': f'Error: {str(e)}'})
        return cleanup_scan()
    finally:
        if scan_running:
            end_time = time.time()
            scan_time = str(timedelta(seconds=round(end_time - start_time)))
            current_scan_info['scan_time'] = scan_time
            return cleanup_scan()

@socketio.on('connect')
def handle_connect():
    print("A client connected")
    emit('message', {'data': 'Welcome to the real-time cybersecurity server!'})
    
@app.route('/userlog', methods=['GET', 'POST'])
def userlog():
    if request.method == 'POST':

        connection = sqlite3.connect('user_data.db')
        cursor = connection.cursor()

        name = request.form['name']
        password = request.form['password']

        query = "SELECT name, password FROM user WHERE name = '"+name+"' AND password= '"+password+"'"
        cursor.execute(query)

        result = cursor.fetchall()

        if result:
            return render_template('templates/home.html')
        else:
            return render_template('templates/index.html', msg='Sorry, Incorrect Credentials Provided,  Try Again')

    return render_template('templates/index.html')


@app.route('/userreg', methods=['GET', 'POST'])
def userreg():
    if request.method == 'POST':

        connection = sqlite3.connect('user_data.db')
        cursor = connection.cursor()

        name = request.form['name']
        password = request.form['password']
        mobile = request.form['phone']
        email = request.form['email']
        
        print(name, mobile, email, password)

        command = """CREATE TABLE IF NOT EXISTS user(name TEXT, password TEXT, mobile TEXT, email TEXT)"""
        cursor.execute(command)

        cursor.execute("INSERT INTO user VALUES ('"+name+"', '"+password+"', '"+mobile+"', '"+email+"')")
        connection.commit()

        return render_template('templates/index.html', msg='Successfully Registered')
    
    return render_template('templates/index.html')


@app.route('/ANN', methods=['GET', 'POST'])
def ANN():
    import numpy as np
    if request.method == 'POST':
        Link = request.form['Link']
        print(Link)
        def preprocess_url(url):
            feature_extractor = FeatureExtraction(url)
            features = feature_extractor.getFeaturesList()
            return np.array(features).reshape(1, -1)

        # Function to predict whether the URL is phishing or not
        def predict_phishing(url):
            # Preprocess the URL and extract features
            features = preprocess_url(url)
            
            # Use the trained model to make predictions
            prediction = model.predict(features)
            
            # Get class probabilities
            probability_non_phishing = prediction[0][0]
            probability_phishing = 1 - probability_non_phishing
            
            # Round the prediction if it's a binary classification problem
            prediction_binary = np.round(prediction)
            
            return prediction_binary, probability_phishing, probability_non_phishing

        # Example URL
        # url = input("Enter the URL: ")

        # Predict whether the URL is phishing or not
        prediction, probability_phishing, probability_non_phishing = predict_phishing(Link)
        # Convert probabilities to percentages
        probability_phishing_percentage = probability_phishing * 100

        probability_non_phishing_percentage = probability_non_phishing * 100

        if prediction == 1:
            res=f"The URL is {probability_non_phishing_percentage:.2f} % SAFE "
        else:
            res=f"The URL is {probability_phishing_percentage:.2f} % NOT SAFE"
        return render_template('templates/ann.html', res=res, url=Link)
    return render_template('templates/ann.html', msg="You are in ANN page")

@app.route('/logout')
def logout():
    return render_template('templates/index.html')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/project')
def project():
    return render_template('project.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/vulnerability_scanner')
def vulnerability_scanner():
    return render_template('vulnerability_scanner.html', attacks=attacks)

@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_running
    if scan_running:
        return jsonify({"error": "Scan already running."}), 400

    target_url = request.form['target_url']
    scan_all_pages = request.form.get('scan_all_pages') == 'on'
    attack_choice = request.form['attack_choice']
    
    # Run the scan in a separate thread
    thread = threading.Thread(target=run_scan_live, args=(target_url, attack_choice, scan_all_pages))
    thread.daemon = True
    thread.start()
    
    return jsonify({"message": "Scan started successfully."}), 200


@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    global scan_running
    
    if not scan_running:
        return jsonify({"message": "No scan running"}), 400
        
    scan_running = False
    socketio.emit('log', {'log': 'Stopping scan...'})
    
    try:
        time.sleep(0.5)  # Wait briefly for scan to clean up
        report_filename = cleanup_scan()
        
        if report_filename:
            print(f"Scan stopped, report generated: {report_filename}")  # Debug print
            return jsonify({
                "message": "Scan stopped successfully",
                "report_url": report_filename
            })
        else:
            return jsonify({
                "message": "Scan stopped but report generation failed"
            }), 500
            
    except Exception as e:
        print(f"Error in stop_scan: {e}")
        return jsonify({
            "message": f"Error stopping scan: {str(e)}"
        }), 500

# Update the download_report route
@app.route('/download/<filename>')
def download_report(filename):
    try:
        reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
        filepath = os.path.join(reports_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"Report not found: {filepath}")  # Debug print
            return "Report not found", 404
            
        format_type = request.args.get('format', 'html')
        print(f"Downloading report: {filepath} as {format_type}")  # Debug print
        
        if format_type == 'pdf':
            try:
                pdf_options = {
                    'page-size': 'A4',
                    'margin-top': '0.75in',
                    'margin-right': '0.75in',
                    'margin-bottom': '0.75in',
                    'margin-left': '0.75in',
                    'encoding': "UTF-8",
                    'no-outline': None,
                    'enable-local-file-access': None
                }
                
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as pdf_file:
                    with open(filepath, 'r', encoding='utf-8') as html_file:
                        html_content = html_file.read()
                    
                    pdfkit.from_string(html_content, pdf_file.name, options=pdf_options)
                    
                    return send_file(
                        pdf_file.name,
                        as_attachment=True,
                        download_name=filename.replace('.html', '.pdf'),
                        mimetype='application/pdf'
                    )
            except Exception as e:
                print(f"PDF generation error: {str(e)}")
                return send_file(filepath, as_attachment=True)
        else:
            return send_file(filepath, as_attachment=True)
    except Exception as e:
        print(f"Download error: {str(e)}")
        return "Error downloading report", 500

# Update the view_report route
@app.route('/view_report/<filename>')
def view_report(filename):
    try:
        reports_dir = os.path.join(os.getcwd(), 'static', 'reports')
        filepath = os.path.join(reports_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"Report not found for viewing: {filepath}")  # Debug print
            return "Report not found", 404
            
        with open(filepath, 'r', encoding='utf-8') as f:
            report_content = f.read()
        return report_content
    except Exception as e:
        print(f"View report error: {str(e)}")
        return "Error viewing report", 500

class DDoSProtection:
    def __init__(self):
        self.request_counts = defaultdict(list)
        self.syn_counts = defaultdict(list)
        self.blocked_ips = set()
        self.request_threshold = 30  # Lowered threshold
        self.syn_threshold = 20  # Lowered threshold
        self.time_window = 2  # Reduced time window
        self.lock = threading.Lock()
        self.attack_history = []
        self.attack_types = {
            'http_flood': False,
            'syn_flood': False
        }
        self.last_cleanup = time.time()
        self.half_open_connections = defaultdict(int)
        self.request_cache = {}  # Cache for rate limiting

    def record_request(self, ip):
        current_time = time.time()
        
        with self.lock:
            # Rate limiting check
            if ip in self.request_cache:
                last_request_time = self.request_cache[ip]
                if current_time - last_request_time < 0.1:  # Minimum 100ms between requests
                    return True
            
            self.request_cache[ip] = current_time
            
            # Clean old requests first
            self.cleanup_old_requests(ip)
            
            # Record HTTP request
            self.request_counts[ip].append(current_time)
            
            # Calculate requests per second with a sliding window
            recent_requests = len([t for t in self.request_counts[ip] 
                                 if current_time - t <= 1])
            
            # Immediate block for extremely high rates
            if recent_requests > self.request_threshold * 2:
                self.blocked_ips.add(ip)
                self.attack_types['http_flood'] = True
                self.record_attack(ip, 'http_flood')
                print(f"HTTP Flood detected and blocked from {ip}")
                return True
            
            # Progressive rate limiting
            if recent_requests > self.request_threshold:
                probability_block = (recent_requests - self.request_threshold) / self.request_threshold
                if random.random() < probability_block:
                    return True
            
            return False

    def cleanup_old_requests(self, ip):
        current_time = time.time()
        # Clean old requests
        if ip in self.request_counts:
            self.request_counts[ip] = [t for t in self.request_counts[ip] 
                                     if current_time - t <= self.time_window]
        if ip in self.syn_counts:
            self.syn_counts[ip] = [t for t in self.syn_counts[ip] 
                                 if current_time - t <= self.time_window]
        # Clean old cache entries
        for cached_ip in list(self.request_cache.keys()):
            if current_time - self.request_cache[cached_ip] > self.time_window:
                del self.request_cache[cached_ip]

    def block_attack_sources(self):
        """Block all detected attack sources"""
        with self.lock:
            blocked_count = len(self.blocked_ips)
            
            # Reset counters and flags
            self.request_counts.clear()
            self.syn_counts.clear()
            self.half_open_connections.clear()
            self.request_cache.clear()
            self.attack_types['http_flood'] = False
            self.attack_types['syn_flood'] = False
            
            return blocked_count

# Create a single instance
ddos_protection = DDoSProtection()

@app.before_request
def check_for_ddos():
    if request.endpoint != 'static':  # Skip static file requests
        ip = request.remote_addr
        
        # Get protection status from session
        protection_enabled = session.get('ddos_protection_enabled', False)
        
        # Only perform DDoS checks if protection is enabled
        if protection_enabled:
            # Skip DDoS check for certain endpoints
            skip_endpoints = ['api.ddos.stats', 'api.ddos.block_attacks']
            if request.endpoint in skip_endpoints:
                return None
            
            try:
                if ddos_protection.is_ip_blocked(ip):
                    return jsonify({'error': 'IP blocked due to suspicious activity'}), 403
                
                if ddos_protection.record_request(ip):
                    return jsonify({'error': 'Too many requests'}), 429
            except Exception as e:
                print(f"Error in DDoS check: {e}")
                # Allow request through on error to prevent complete service disruption
                return None
        
        return None

@app.route('/api/ddos/stats')
def get_ddos_stats():
    return jsonify(ddos_protection.get_stats())

@app.route('/api/ddos/toggle', methods=['POST'])
def toggle_ddos_protection():
    data = request.get_json()
    enabled = data.get('enabled', False)
    
    # Make session permanent
    session.permanent = True
    session['ddos_protection_enabled'] = enabled
    
    if enabled:
        # Clear any existing attack data when enabling protection
        ddos_protection.request_counts.clear()
        ddos_protection.syn_counts.clear()
        ddos_protection.blocked_ips.clear()
        ddos_protection.attack_types['http_flood'] = False
        ddos_protection.attack_types['syn_flood'] = False
    
    return jsonify({'status': 'success', 'enabled': enabled})

@app.route('/ddos')
def ddos():
    # Make session permanent when accessing the page
    session.permanent = True
    return render_template('DDoS.html')

@app.route('/extension')
def extension():
    return render_template('extension.html')

# Add new route for blocking attacks
@app.route('/api/ddos/block_attacks', methods=['POST'])
def block_attacks():
    try:
        blocked_count = ddos_protection.block_attack_sources()
        return jsonify({
            'status': 'success',
            'message': f'Successfully blocked {blocked_count} attack sources',
            'blocked_count': blocked_count
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    socketio.run(app, debug=True)
