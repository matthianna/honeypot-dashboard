# Honeypot Monitoring Dashboard

A comprehensive web-based dashboard for monitoring and analyzing honeypot data from multiple sources including Cowrie, Dionaea, Galah, Heralding, RDPY, and firewall logs.

![Dashboard Preview](docs/dashboard-preview.png)

## Features

### 📊 Dashboard
- Real-time attack statistics and trends
- Geographic distribution of attacks with interactive maps
- Protocol distribution analysis
- Hourly attack heatmap
- MITRE ATT&CK coverage visualization
- Threat intelligence summary

### 🗺️ Live Attack Map
- Real-time visualization of attacks worldwide
- WebSocket-based live feed
- Attack source geolocation

### 🐚 Cowrie SSH/Telnet Honeypot
- Session analysis and duration metrics
- Command categorization and MITRE mapping
- Login attempt analysis (success/failure)
- Credential analysis
- Weak algorithm detection
- SSH client fingerprinting (HASSH)
- Variant comparison (plain, LLM, OpenAI)

### 🦠 Dionaea Malware Honeypot
- Service distribution analysis
- Connection state monitoring
- Attack source analysis

### 🤖 Galah Web Honeypot
- AI success rate trends
- Path category analysis
- HTTP client fingerprinting
- LLM response analysis

### 📡 Heralding Credential Honeypot
- Protocol statistics
- Attempt distribution analysis

### 🖥️ RDPY RDP Honeypot
- Connection pattern analysis
- Attack velocity metrics

### 🔥 Firewall Analytics
- Rule statistics
- Action timeline
- TCP flags analysis
- TTL-based OS fingerprinting
- Packet size distribution

### 👤 Attacker Profiles
- Country-based attacker organization
- Detailed attacker profiles
- Activity timelines
- Session details and raw logs

## Tech Stack

### Backend
- **FastAPI** - Modern Python web framework
- **Elasticsearch** - Data storage and querying
- **Python 3.11+** - Backend runtime

### Frontend
- **React 18** - UI framework
- **TypeScript** - Type-safe JavaScript
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Recharts** - Data visualization
- **React Simple Maps** - Geographic visualizations
- **Lucide React** - Icons

### Infrastructure
- **Docker & Docker Compose** - Containerization
- **Nginx** - Frontend serving and reverse proxy

## Prerequisites

- Docker and Docker Compose
- Elasticsearch instance with honeypot data
- Node.js 18+ (for local development)
- Python 3.11+ (for local development)

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/honeypot-web.git
cd honeypot-web
```

### 2. Configure environment

Copy the example environment file and configure it:

```bash
cp env.example .env
```

Edit `.env` with your settings:

```env
# Elasticsearch Configuration
ELASTICSEARCH_HOST=your-elasticsearch-host
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_USERNAME=your-username
ELASTICSEARCH_PASSWORD=your-password

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Admin credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password

# Frontend API URL
VITE_API_URL=http://localhost:8000
```

### 3. Start the application

```bash
docker compose up -d
```

The application will be available at:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

### 4. Access the dashboard

Open your browser and navigate to `http://localhost:3000`. Log in with your configured admin credentials.

## Development Setup

### Backend Development

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev
```

## Project Structure

```
honeypot-web/
├── backend/
│   ├── app/
│   │   ├── auth/           # Authentication (JWT)
│   │   ├── models/         # Pydantic schemas
│   │   ├── routers/        # API endpoints
│   │   │   ├── attacker.py
│   │   │   ├── attackmap.py
│   │   │   ├── cowrie.py
│   │   │   ├── dashboard.py
│   │   │   ├── dionaea.py
│   │   │   ├── firewall.py
│   │   │   ├── galah.py
│   │   │   ├── heralding.py
│   │   │   └── rdpy.py
│   │   ├── services/       # Business logic
│   │   │   ├── elasticsearch.py
│   │   │   └── mitre.py
│   │   └── main.py
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/     # Reusable components
│   │   ├── context/        # React context (Auth)
│   │   ├── hooks/          # Custom hooks
│   │   ├── pages/          # Page components
│   │   ├── services/       # API client
│   │   └── types/          # TypeScript types
│   ├── Dockerfile
│   └── package.json
├── docker-compose.yml
├── env.example
└── README.md
```

## Elasticsearch Index Requirements

The dashboard expects the following Elasticsearch indices:

| Honeypot | Index Pattern |
|----------|---------------|
| Cowrie | `cowrie-*` |
| Dionaea | `dionaea-*` |
| Galah | `galah-*` |
| Heralding | `heralding-*` |
| RDPY | `rdpy-*` |
| Firewall | `filebeat-*` |

### Required Fields

Each honeypot index should contain standard ECS (Elastic Common Schema) fields plus honeypot-specific fields. Key fields include:

- `@timestamp` - Event timestamp
- `source.ip` - Attacker IP address
- `source.geo.*` - Geolocation data
- Honeypot-specific fields (see individual honeypot documentation)

## API Documentation

Once the backend is running, access the interactive API documentation at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Configuration

### Session Timeout

The frontend includes a session timeout warning. Configure the timeout in the backend JWT settings.

### Time Range

The dashboard supports multiple time ranges:
- Last 15 minutes, 1 hour, 4 hours, 12 hours
- Last 1 day, 7 days, 30 days
- Custom range

## Security Considerations

1. **Change default credentials** - Update `ADMIN_USERNAME` and `ADMIN_PASSWORD` in production
2. **Secure JWT secret** - Use a strong, unique `JWT_SECRET_KEY`
3. **HTTPS** - Use a reverse proxy with SSL/TLS in production
4. **Elasticsearch security** - Enable authentication on your Elasticsearch cluster
5. **Firewall** - Restrict access to the dashboard and Elasticsearch

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Cowrie SSH/Telnet Honeypot](https://github.com/cowrie/cowrie)
- [Dionaea](https://github.com/DinoTools/dionaea)
- [Galah](https://github.com/0x4D31/galah)
- [Heralding](https://github.com/johnnykv/heralding)
- [MITRE ATT&CK](https://attack.mitre.org/)

