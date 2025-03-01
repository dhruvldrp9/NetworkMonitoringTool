from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import time
from network_analyzer import NetworkAnalyzer

app = Flask(__name__)
socketio = SocketIO(app)

# Global analyzer instance
analyzer = None
analyzer_thread = None

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

def emit_stats():
    """Emit statistics periodically"""
    while True:
        if analyzer and analyzer.stats_collector:
            stats = analyzer.stats_collector.get_stats()
            socketio.emit('stats_update', stats)
        time.sleep(1)

def start_analyzer():
    """Start the network analyzer in a separate thread"""
    global analyzer, analyzer_thread
    
    if analyzer is None:
        analyzer = NetworkAnalyzer()
        
        # Override packet processing to emit events
        def process_packet_with_events(packet):
            packet_info = analyzer.packet_analyzer.analyze_packet(packet)
            if packet_info:
                threats = analyzer.threat_detector.detect_threats(packet_info)
                if threats:
                    for threat in threats:
                        socketio.emit('threat_detected', threat)
                socketio.emit('packet_processed', packet_info)
                analyzer.stats_collector.update_stats(packet_info)
        
        analyzer.process_packet = process_packet_with_events
        
        # Start the analyzer thread
        analyzer_thread = threading.Thread(target=analyzer.simulate_traffic)
        analyzer_thread.daemon = True
        analyzer_thread.start()
        
        # Start stats emission thread
        stats_thread = threading.Thread(target=emit_stats)
        stats_thread.daemon = True
        stats_thread.start()

if __name__ == '__main__':
    start_analyzer()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
