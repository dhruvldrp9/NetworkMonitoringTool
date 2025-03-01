#!/usr/bin/env python3
from flask import Flask, render_template, send_file, request, jsonify
from flask_socketio import SocketIO
import threading
import time
import logging
import os
import sys
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import json

# Configure logging with more detail
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure all imported modules use the same logging config
logging.getLogger('flask').setLevel(logging.INFO)
logging.getLogger('werkzeug').setLevel(logging.INFO)
logging.getLogger('socketio').setLevel(logging.INFO)
logging.getLogger('engineio').setLevel(logging.INFO)

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*', logger=True, engineio_logger=True)

# Global variables
analyzer = None
analyzer_thread = None
stats_thread = None
simulation_mode = True  # Default to simulation mode

@app.route('/')
def dashboard():
    """Serve the dashboard page"""
    logger.info("Dashboard page accessed")
    # Ensure analyzer is running
    if not analyzer:
        start_analyzer()
    return render_template('dashboard.html')

@app.route('/api/initial-stats')
def get_initial_stats():
    """Get initial statistics for dashboard"""
    try:
        if analyzer and analyzer.stats_collector:
            stats = analyzer.stats_collector.get_stats()
            return jsonify(stats)
        return jsonify({'error': 'Analyzer not initialized'}), 503
    except Exception as e:
        logger.error(f"Error getting initial stats: {e}", exc_info=True)
        return jsonify({'error': 'Failed to get statistics'}), 500

@app.route('/api/toggle-mode', methods=['POST'])
def toggle_mode():
    """Toggle between simulation and real network tracking modes"""
    global simulation_mode
    try:
        simulation_mode = request.json.get('simulation', True)
        if analyzer:
            analyzer.set_simulation_mode(simulation_mode)
        return jsonify({
            'success': True,
            'mode': 'simulation' if simulation_mode else 'real'
        })
    except Exception as e:
        logger.error(f"Error toggling mode: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():
    """Generate a PDF report of the current security analysis"""
    try:
        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=landscape(letter),
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30
        )
        styles = getSampleStyleSheet()
        elements = []

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        )
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=18,
            spaceAfter=12
        )
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=12,
            leading=14
        )

        # Title
        elements.append(Paragraph("Network Security Analysis Report", title_style))
        elements.append(Spacer(1, 12))

        # Report timestamp and summary
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(f"Generated on: {timestamp}", normal_style))
        elements.append(Spacer(1, 12))

        # Get stats with error handling
        stats = {}
        if analyzer and hasattr(analyzer, 'stats_collector'):
            try:
                stats = analyzer.stats_collector.get_stats()
                logger.debug(f"Retrieved stats for report: {stats}")
            except Exception as e:
                logger.error(f"Error getting stats: {e}", exc_info=True)
                stats = {}

        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        summary_text = """
        This report provides a comprehensive analysis of network traffic patterns,
        security threats, and anomalies detected by our advanced monitoring system.
        The analysis includes both traditional threat detection and machine learning-based
        anomaly detection results.
        """
        elements.append(Paragraph(summary_text, normal_style))
        elements.append(Spacer(1, 20))

        # Traffic Overview
        elements.append(Paragraph("Traffic Overview", heading_style))
        traffic_data = [
            ["Metric", "Value"],
            ["Total Packets", str(stats.get('general', {}).get('total_packets', 0))],
            ["Packets/Second", f"{stats.get('general', {}).get('packets_per_second', 0):.2f}"],
            ["Total Bytes", str(stats.get('general', {}).get('total_bytes', 0))],
            ["Unique IPs", str(stats.get('general', {}).get('unique_ips', 0))],
            ["Average Packet Size", f"{stats.get('general', {}).get('avg_packet_size', 0):.2f} bytes"]
        ]
        table = Table(traffic_data, colWidths=[4*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(table)
        elements.append(Spacer(1, 20))

        # Protocol Distribution
        if 'protocols' in stats:
            elements.append(Paragraph("Protocol Distribution", heading_style))
            protocol_data = [["Protocol", "Count"]]
            for protocol, count in stats['protocols'].items():
                protocol_data.append([protocol, str(count)])
            table = Table(protocol_data, colWidths=[4*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.blue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)
            elements.append(Spacer(1, 20))

        # Security Threats
        elements.append(Paragraph("Recent Security Threats", heading_style))
        try:
            threats = analyzer.db_manager.get_recent_threats(limit=10)
            if threats:
                threat_data = [["Time", "Type", "Source", "Severity", "Details"]]
                for threat in threats:
                    threat_data.append([
                        threat.timestamp.strftime("%H:%M:%S"),
                        threat.type,
                        threat.source,
                        threat.severity,
                        threat.details[:50] + "..." if len(threat.details) > 50 else threat.details
                    ])
                table = Table(threat_data, colWidths=[1.5*inch, 2*inch, 2*inch, 1.5*inch, 3*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No recent threats detected", normal_style))
        except Exception as e:
            logger.error(f"Error getting threats: {e}", exc_info=True)
            elements.append(Paragraph("Error retrieving threat data", normal_style))

        # ML Anomalies
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Machine Learning Anomaly Detection", heading_style))
        try:
            anomalies = analyzer.db_manager.get_recent_anomalies(limit=10)
            if anomalies:
                anomaly_data = [["Time", "Source", "Confidence", "Details"]]
                for anomaly in anomalies:
                    anomaly_data.append([
                        anomaly.timestamp.strftime("%H:%M:%S"),
                        anomaly.source,
                        f"{anomaly.confidence:.2f}",
                        anomaly.details[:50] + "..." if len(anomaly.details) > 50 else anomaly.details
                    ])
                table = Table(anomaly_data, colWidths=[2*inch, 2*inch, 2*inch, 4*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.purple),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(table)
            else:
                elements.append(Paragraph("No recent anomalies detected", normal_style))
        except Exception as e:
            logger.error(f"Error getting anomalies: {e}", exc_info=True)
            elements.append(Paragraph("Error retrieving anomaly data", normal_style))

        # Network Performance
        if 'performance' in stats:
            elements.append(Spacer(1, 20))
            elements.append(Paragraph("Network Performance Metrics", heading_style))
            perf_data = [["Metric", "Value"]]
            perf = stats['performance']
            perf_data.extend([
                ["Packet Loss Rate", f"{perf.get('packet_loss', 0):.2f}%"],
                ["Network Latency", f"{perf.get('latency', 0):.2f}ms"],
                ["Bandwidth Usage", f"{perf.get('bandwidth', 0):.2f} Mbps"]
            ])
            table = Table(perf_data, colWidths=[4*inch, 4*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.green),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(table)

        # Recommendations
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Security Recommendations", heading_style))
        mode_text = "Simulation Mode" if simulation_mode else "Real Network Traffic Mode"
        recommendations = f"""
        Current Operating Mode: {mode_text}

        Based on the analysis of network traffic and detected threats, we recommend:
        1. Regular monitoring of high-risk IPs identified in this report
        2. Implementation of additional security measures for frequently targeted services
        3. Investigation of any unusual protocol distributions
        4. Follow-up on high-confidence ML anomaly detections
        """
        elements.append(Paragraph(recommendations, normal_style))

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        # Generate filename with timestamp
        filename = f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'

        try:
            response = send_file(
                buffer,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            return response
        except Exception as e:
            logger.error(f"Error sending PDF file: {e}", exc_info=True)
            return jsonify({"error": "Failed to send report"}), 500

    except Exception as e:
        logger.error(f"Error generating PDF report: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

def emit_stats():
    """Emit statistics periodically via Socket.IO"""
    logger.info("Starting stats emission thread")
    while True:
        try:
            if analyzer and analyzer.stats_collector:
                stats = analyzer.stats_collector.get_stats()
                logger.debug(f"Emitting stats update: {stats}")
                socketio.emit('stats_update', stats)

                # Log attack pattern data specifically
                if 'attacks' in stats:
                    logger.debug(f"Attack pattern data: {stats['attacks']}")

                # Log connection data
                if 'connections' in stats:
                    logger.debug(f"Connection matrix size: {len(stats.get('connections', {}).get('counts', []))} data points")
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in stats emission: {e}", exc_info=True)
            time.sleep(1)  # Prevent rapid retries on persistent errors

def start_analyzer():
    """Start the network analyzer in a separate thread"""
    global analyzer, analyzer_thread, stats_thread

    try:
        if analyzer is None:
            logger.info("Initializing Network Analyzer...")
            from network_analyzer import NetworkAnalyzer
            analyzer = NetworkAnalyzer()

            def process_packet_with_events(packet):
                try:
                    packet_info = analyzer.packet_analyzer.analyze_packet(packet)
                    if packet_info:
                        logger.debug(f"Processing packet: {packet_info}")

                        # Emit packet processed event
                        socketio.emit('packet_processed', packet_info)

                        # Traditional threats
                        threats = analyzer.threat_detector.detect_threats(packet_info)
                        security_threats = analyzer.security_integrator.analyze_packet(packet_info)

                        if threats:
                            for threat in threats:
                                logger.info(f"Traditional threat detected: {threat}")
                                socketio.emit('threat_detected', {
                                    'type': threat['type'],
                                    'source': threat['source'],
                                    'details': threat['details'],
                                    'severity': threat.get('severity', 'medium'),
                                    'category': threat.get('category', 'unknown')
                                })

                        if security_threats:
                            for threat in security_threats:
                                logger.info(f"Security integration threat detected: {threat}")
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
                                logger.info(f"ML anomaly detected: {anomaly}")
                                socketio.emit('threat_detected', {
                                    'type': anomaly['type'],
                                    'source': anomaly['source'],
                                    'details': anomaly['details'],
                                    'severity': 'high' if anomaly.get('confidence', 0) > 0.8 else 'medium',
                                    'category': 'ml_anomaly'
                                })

                        # Update statistics
                        analyzer.stats_collector.update_stats(packet_info)
                except Exception as e:
                    logger.error(f"Error processing packet: {e}", exc_info=True)

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
        logger.error(f"Error starting analyzer: {e}", exc_info=True)
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
        logger.error(f"Failed to start dashboard: {e}", exc_info=True)
        sys.exit(1)