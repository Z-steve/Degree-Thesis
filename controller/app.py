from flask import Flask, render_template, jsonify, request
from model.data_manager import DataManager
from model.packet_processor import PacketProcessor
from model.network_scanner import NetworkScanner

app = Flask(__name__, template_folder="../view/templates", static_folder="../view/static")
data_manager = None
packet_processor = None
scanner = None  # Placeholder


def set_data_manager(dm):
    global data_manager
    data_manager = dm

def set_packet_processor(pp):
    global packet_processor
    packet_processor = pp

def set_scanner(sc):
    global scanner
    scanner = sc

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/dns_table')
def dns_table():
    return render_template('dnsexpirationtable.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/get_dns_table', methods=['GET'])
def get_dns_table():
    return jsonify(data_manager.dns_expiration_table)

@app.route('/api/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    if ip:
        data_manager.add_blocked_ip(ip)
        return jsonify({"status": "success", "message": f"Blocked IP: {ip}"})
    return jsonify({"status": "error", "message": "IP not provided"}), 400

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    ip = request.json.get('ip')
    if ip:
        data_manager.remove_blocked_ip(ip)
        return jsonify({"status": "success", "message": f"Unblocked IP: {ip}"})
    return jsonify({"status": "error", "message": "IP not provided"}), 400

@app.route('/api/get_blocked_ips', methods=['GET'])
def get_blocked_ips():
    return jsonify(data_manager.blocked_ips)

@app.route('/api/get_allowlisted_users', methods=['GET'])
def get_allowlisted_users():
    return jsonify(data_manager.allowlisted_users)

@app.route('/api/add_allowlisted_user', methods=['POST'])
def add_allowlisted_user():
    ip = request.json.get('ip')
    if ip:
        data_manager.add_allowlisted_user(ip)
        return jsonify({"status": "success", "message": f"Added allowlisted user: {ip}"})
    return jsonify({"status": "error", "message": "IP not provided"}), 400

@app.route('/api/remove_allowlisted_user', methods=['POST'])
def remove_allowlisted_user():
    ip = request.json.get('ip')
    if ip:
        data_manager.remove_allowlisted_user(ip)
        return jsonify({"status": "success", "message": f"Removed allowlisted user: {ip}"})
    return jsonify({"status": "error", "message": "IP not provided"}), 400

@app.route('/api/get_metrics', methods=['GET'])
def get_metrics():
    with packet_processor.lock:
        avg_latency = (sum(packet_processor.latencies) / len(packet_processor.latencies)
                       if packet_processor.latencies else 0)
        avg_cpu = (sum(packet_processor.cpu_usages) / len(packet_processor.cpu_usages)
                   if packet_processor.cpu_usages else 0)
        avg_memory = (sum(packet_processor.memory_usages) / len(packet_processor.memory_usages)
                      if packet_processor.memory_usages else 0)
        return jsonify({
            "packet_count": packet_processor.packet_count,
            "avg_latency": avg_latency,
            "avg_cpu": avg_cpu,
            "avg_memory": avg_memory
        })

@app.route('/api/get_topology', methods=['GET'])
def get_topology():
    devices = scanner.get_devices()
    app.logger.info(f"Topology devices sent: {devices}")
    return jsonify(devices)

@app.route('/api/get_logs', methods=['GET'])
def get_logs():
    return jsonify(data_manager.logs)


@app.route('/api/get_allowlisted_domains', methods=['GET'])
def get_allowlisted_domains():
    return jsonify(data_manager.allowlisted_domains)

@app.route('/api/add_allowlisted_domain', methods=['POST'])
def add_allowlisted_domain():
    domain = request.json.get('domain')
    if domain:
        data_manager.add_allowlisted_domain(domain)
        return jsonify({"status": "success", "message": f"Added allowlisted domain: {domain}"})
    return jsonify({"status": "error", "message": "Domain not provided"}), 400

@app.route('/api/remove_allowlisted_domain', methods=['POST'])
def remove_allowlisted_domain():
    domain = request.json.get('domain')
    if domain:
        data_manager.remove_allowlisted_domain(domain)
        return jsonify({"status": "success", "message": f"Removed allowlisted domain: {domain}"})
    return jsonify({"status": "error", "message": "Domain not provided"}), 400