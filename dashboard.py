from flask import Flask, render_template, send_file, request, jsonify
from flask_socketio import SocketIO
import threading
import time
import logging
import os
import sys
from io import BytesIO
import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime

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

@app.route('/generate_report', methods=['POST'])
def generate_report():
    try:
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        elements.append(Paragraph("Network Security Analysis Report", title_style))
        elements.append(Spacer(1, 12))

        # Report timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(f"Generated on: {timestamp}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        if analyzer and analyzer.stats_collector:
            stats = analyzer.stats_collector.get_stats()

            # Traffic Overview
            elements.append(Paragraph("Traffic Overview", styles["Heading2"]))
            elements.append(Spacer(1, 12))
            traffic_data = [
                ["Metric", "Value"],
                ["Total Packets", str(stats['general'].get('total_packets', 0))],
                ["Packets/Second", f"{stats['general'].get('packets_per_second', 0):.2f}"],
                ["Total Bytes", str(stats['general'].get('total_bytes', 0))],
                ["Unique IPs", str(len(stats['general'].get('unique_ips', set())))]
            ]
            traffic_table = Table(traffic_data, colWidths=[3*inch, 3*inch])
            traffic_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(traffic_table)
            elements.append(Spacer(1, 20))

            # Recent Threats
            elements.append(Paragraph("Recent Security Threats", styles["Heading2"]))
            elements.append(Spacer(1, 12))
            recent_threats = analyzer.db_manager.get_recent_threats(limit=10)
            if recent_threats:
                threat_data = [["Time", "Type", "Source", "Severity"]]
                for threat in recent_threats:
                    threat_data.append([
                        threat.timestamp.strftime("%H:%M:%S"),
                        threat.type,
                        threat.source,
                        threat.severity
                    ])
                threat_table = Table(threat_data, colWidths=[1.5*inch, 2*inch, 2*inch, 1.5*inch])
                threat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(threat_table)
            else:
                elements.append(Paragraph("No recent threats detected", styles["Normal"]))

            # Anomalies
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("ML-Detected Anomalies", styles["Heading2"]))
            elements.append(Spacer(1, 12))
            recent_anomalies = analyzer.db_manager.get_recent_anomalies(limit=10)
            if recent_anomalies:
                anomaly_data = [["Time", "Type", "Source", "Confidence"]]
                for anomaly in recent_anomalies:
                    anomaly_data.append([
                        anomaly.timestamp.strftime("%H:%M:%S"),
                        anomaly.type,
                        anomaly.source,
                        f"{anomaly.confidence:.2f}"
                    ])
                anomaly_table = Table(anomaly_data, colWidths=[1.5*inch, 2*inch, 2*inch, 1.5*inch])
                anomaly_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(anomaly_table)
            else:
                elements.append(Paragraph("No recent anomalies detected", styles["Normal"]))

        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'security_report_{timestamp}.pdf'
        )
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        return jsonify({"error": "Failed to generate report"}), 500

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
            # Import here to avoid circular imports and allow proper initialization
            from network_analyzer import NetworkAnalyzer
            analyzer = NetworkAnalyzer()

            # Override packet processing to emit events
            def process_packet_with_events(packet):
                try:
                    packet_info = analyzer.packet_analyzer.analyze_packet(packet)
                    if packet_info:
                        # Traditional threats
                        threats = analyzer.threat_detector.detect_threats(packet_info)
                        security_threats = analyzer.security_integrator.analyze_packet(packet_info)

                        if threats:
                            for threat in threats:
                                socketio.emit('threat_detected', {
                                    'type': threat['type'],
                                    'source': threat['source'],
                                    'details': threat['details'],
                                    'severity': threat.get('severity', 'medium'),
                                    'category': threat.get('category', 'unknown')
                                })

                        if security_threats:
                            for threat in security_threats:
                                socketio.emit('threat_detected', {
                                    'type': threat['type'],
                                    'source': threat['source'],
                                    'details': threat['details'],
                                    'severity': threat.get('severity', 'medium'),
                                    'category': 'ids'
                                })

                        # ML-based anomalies
                        anomalies = analyzer.ml_analyzer.detect_anomalies(packet_info)
                        if anomalies:
                            for anomaly in anomalies:
                                socketio.emit('threat_detected', {
                                    'type': anomaly['type'],
                                    'source': anomaly['source'],
                                    'details': anomaly['details'],
                                    'severity': 'high' if anomaly.get('confidence', 0) > 0.8 else 'medium',
                                    'category': 'ml_anomaly'
                                })

                        socketio.emit('packet_processed', packet_info)
                        analyzer.stats_collector.update_stats(packet_info)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")

            analyzer.process_packet = process_packet_with_events

            # Start the analyzer thread
            logger.info("Starting analyzer thread...")
            analyzer_thread = threading.Thread(target=analyzer.simulate_attack_patterns)
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
                    debug=False,  # Set to False to avoid duplicate analyzers
                    use_reloader=False,
                    log_output=True)
    except Exception as e:
        logger.error(f"Failed to start dashboard: {e}")
        sys.exit(1)