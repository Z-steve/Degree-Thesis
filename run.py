from controller.app import app
from model.packet_processor import PacketProcessor
from model.data_manager import DataManager
from config.config import Config
import threading

def main():
    data_manager = DataManager(dns_expiration_file=Config.DNS_EXPIRATION_FILE)
    packet_processor = PacketProcessor(
        data_manager,
        block_threshold=Config.BLOCK_THRESHOLD,
        block_duration=Config.BLOCK_DURATION,
        ttl=Config.TTL
    )
    # Start packet processor in a thread
    processor_thread = threading.Thread(target=packet_processor.start)
    processor_thread.daemon = True
    processor_thread.start()
    # Run Flask app
    app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()