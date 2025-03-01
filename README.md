# Network Security Analysis Platform

A cutting-edge network security analysis platform that combines advanced packet capture, real-time threat visualization, and intelligent anomaly detection.

## Features

- Real-time network traffic monitoring and analysis
- Machine learning-based anomaly detection
- Interactive dashboard with real-time visualizations
- Comprehensive PDF report generation
- Simulation and Real Network modes
- Multi-tool security rule integrations (Suricata, Snort, Zeek)
- Advanced threat detection and visualization

## Setup & Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
- `DATABASE_URL`: PostgreSQL database connection string
- Other environment variables will be automatically configured by Replit

## Usage

### Running the Application

1. Start the application:
```bash
python dashboard.py
```

2. Access the dashboard at `http://localhost:5000`

### Operating Modes

1. **Simulation Mode (Default)**
   - Uses pre-recorded network data
   - Perfect for testing and demonstration
   - Safe to run in any environment

2. **Real Network Mode**
   - Captures live network traffic using Scapy
   - Requires appropriate network access permissions
   - Use with caution in production environments

### Dashboard Features

1. **Traffic Overview**
   - Total packets processed
   - Packets per second
   - Unique IPs detected
   - Average packet size

2. **Security Analysis**
   - Real-time threat detection
   - Protocol distribution
   - Connection heatmap
   - Attack pattern visualization

3. **Reporting**
   - Generate detailed PDF reports
   - Traffic statistics
   - Security incidents
   - Performance metrics

### Generating Reports

1. Click the "Download Report" button in the dashboard
2. Reports include:
   - Traffic overview
   - Security threats
   - ML-based anomalies
   - Network performance metrics
   - Actionable recommendations

## Security Features

1. **Traditional Threat Detection**
   - Signature-based detection
   - Pattern matching
   - Protocol analysis
   - Port scanning detection

2. **Machine Learning Anomaly Detection**
   - Behavioral analysis
   - Traffic pattern recognition
   - Automatic baseline adjustment
   - High-confidence alerts

3. **Deep Packet Inspection**
   - Protocol validation
   - Payload analysis
   - Malicious content detection
   - Data exfiltration prevention

## Performance Optimization

The platform includes several optimizations:
- Efficient packet processing
- Real-time data streaming
- Optimized database queries
- Memory-efficient data structures

## Security Recommendations

1. Regular monitoring of suspicious activities
2. Investigation of high-confidence ML anomalies
3. Following up on repeated connection attempts
4. Implementing suggested security measures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License

MIT License - See LICENSE file for details
