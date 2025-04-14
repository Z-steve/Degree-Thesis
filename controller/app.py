from flask import Flask, render_template, jsonify, request
from model.data_manager import DataManager
from model.packet_processor import PacketProcessor

app = Flask(__name__, template_folder="../view/templates", static_folder="../view/static")
data_manager = None
packet_processor = None

def set_data_manager(dm):
    global data_manager
    data_manager = dm

def set_packet_processor(pp):
    global packet_processor
    packet_processor = pp

@app.route('/')
def index():
    return render_template('index.html')

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
    return jsonify({
        "packet_count": packet_processor.packet_count,
        "avg_latency": (sum(packet_processor.latencies) / len(packet_processor.latencies)
                        if packet_processor.latencies else 0),
        "avg_cpu": (sum(packet_processor.cpu_usages) / len(packet_processor.cpu_usages)
                    if packet_processor.cpu_usages else 0),
        "avg_memory": (sum(packet_processor.memory_usages) / len(packet_processor.memory_usages)
                       if packet_processor.memory_usages else 0)
    })