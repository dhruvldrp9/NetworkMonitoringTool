from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import time
import logging
from network_analyzer import NetworkAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*')

# Global analyzer instance
analyzer = None
analyzer_thread = None

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

def emit_stats():
    """Emit statistics periodically"""
    while True:
        try:
            if analyzer and analyzer.stats_collector:
                stats = analyzer.stats_collector.get_stats()
                socketio.emit('stats_update', stats)
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in stats emission: {e}")

def start_analyzer():
    """Start the network analyzer in a separate thread"""
    global analyzer, analyzer_thread

    try:
        if analyzer is None:
            logger.info("Initializing Network Analyzer...")
            analyzer = NetworkAnalyzer()

            # Override packet processing to emit events
            def process_packet_with_events(packet):
                try:
                    packet_info = analyzer.packet_analyzer.analyze_packet(packet)
                    if packet_info:
                        threats = analyzer.threat_detector.detect_threats(packet_info)
                        if threats:
                            for threat in threats:
                                socketio.emit('threat_detected', {
                                    'type': threat['type'],
                                    'source': threat['source'],
                                    'details': threat['details'],
                                    'severity': threat.get('severity', 'medium'),
                                    'category': threat.get('category', 'unknown')
                                })
                        socketio.emit('packet_processed', packet_info)
                        analyzer.stats_collector.update_stats(packet_info)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")

            analyzer.process_packet = process_packet_with_events

            # Start the analyzer thread
            logger.info("Starting analyzer thread...")
            analyzer_thread = threading.Thread(target=analyzer.simulate_traffic)
            analyzer_thread.daemon = True
            analyzer_thread.start()

            # Start stats emission thread
            logger.info("Starting stats emission thread...")
            stats_thread = threading.Thread(target=emit_stats)
            stats_thread.daemon = True
            stats_thread.start()

    except Exception as e:
        logger.error(f"Error starting analyzer: {e}")
        raise

if __name__ == '__main__':
    try:
        logger.info("Starting Network Traffic Analyzer Dashboard...")
        start_analyzer()
        socketio.run(app, 
                    host='0.0.0.0', 
                    port=5000, 
                    debug=True, 
                    use_reloader=False,
                    log_output=True)
    except Exception as e:
        logger.error(f"Failed to start dashboard: {e}")
        raise