# Network Security Analysis Platform

![Network_Monitoring_Tool](https://github.com/user-attachments/assets/1319728a-7d6a-4608-9d7a-77d166d5e95c)


A cutting-edge network security analysis platform that combines advanced packet capture, real-time threat visualization, and intelligent anomaly detection.

## Features

- Real-time network traffic monitoring and visualization
- Simulation and Real Network tracking modes
- Machine learning-based anomaly detection
- Interactive dashboard with real-time updates
- Comprehensive PDF report generation
- Multi-tool security rule integrations (Suricata, Snort, Zeek)
- Advanced threat detection and visualization
- Comprehensive PDF report generation
- Simulation and Real Network modes
- Multi-tool security rule integrations (Suricata, Snort, Zeek)
- Advanced threat detection and visualization


## Prerequisites

- Python 3.11 or higher
- PostgreSQL database
- libpcap-dev (for packet capture capabilities)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-security-platform.git
cd network-security-platform
```

2. Run the installation script:
```bash
chmod +x scripts/install_dependencies.sh
./scripts/install_dependencies.sh
```

3. Set up environment variables in `.env`:
```
DATABASE_URL=postgresql://user:password@localhost/dbname
```

## Running the Application

1. Start the network analyzer:
```bash
python network_analyzer.py
```

2. Start the dashboard:
```bash
python dashboard.py
```

3. Access the dashboard at `http://localhost:5000`

## Usage

### Network Tracking Modes

1. **Simulation Mode (Default)**
   - Uses pre-recorded network data
   - Perfect for testing and demonstration
   - Safe to run in any environment

2. **Real Network Mode**
   - Captures live network traffic using Scapy
   - Requires appropriate network access permissions
   - Use with caution in production environments

### Generating Reports

1. Click the "Download Report" button in the dashboard
2. Reports include:
   - Traffic overview
   - Security incidents
   - ML-based anomalies
   - Network performance metrics
   - Actionable recommendations

## Project Structure

```
.
├── data/
│   └── rules/          # Detection rules and patterns
├── models/             # ML models and training data
├── scripts/            # Utility scripts
├── static/            
│   ├── css/           # Stylesheets
│   └── js/            # JavaScript files
├── templates/          # HTML templates
├── CONTRIBUTING.md     # Contribution guidelines
├── DOCUMENTATION.md    # Technical documentation
├── README.md          # This file
└── requirements.txt    # Python dependencies
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Documentation

For detailed technical documentation, please refer to [DOCUMENTATION.md](DOCUMENTATION.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
