# Honeypot Monitoring System - Implementation Report

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Backend Implementation](#backend-implementation)
4. [Frontend Implementation](#frontend-implementation)
5. [Data Flow](#data-flow)
6. [Key Features](#key-features)
7. [API Design](#api-design)
8. [Authentication](#authentication)
9. [Elasticsearch Integration](#elasticsearch-integration)
10. [Challenges & Solutions](#challenges--solutions)

---

## System Overview

The Honeypot Monitoring System is a full-stack web application designed to visualize and analyze data from multiple honeypot sensors deployed in a network security research environment. It provides real-time monitoring, attack analysis, and thesis-ready reporting capabilities.

### Supported Honeypots
| Honeypot | Protocol | Purpose |
|----------|----------|---------|
| **Cowrie** | SSH/Telnet | Medium-interaction SSH honeypot with LLM variants (Plain, OpenAI, Ollama) |
| **Dionaea** | Multi-protocol | Low-interaction honeypot capturing malware and exploits |
| **Galah** | HTTP/HTTPS | Web honeypot with LLM-powered responses |
| **RDPY** | RDP | Remote Desktop Protocol honeypot |
| **Heralding** | Multi-protocol | Credential capturing honeypot |
| **Firewall** | Network | PFSense firewall log analysis |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (React)                         │
│                    Port 3000 (nginx container)                   │
├─────────────────────────────────────────────────────────────────┤
│                              │                                   │
│                         REST API                                 │
│                              ▼                                   │
├─────────────────────────────────────────────────────────────────┤
│                      Backend (FastAPI)                           │
│                        Port 8000                                 │
├─────────────────────────────────────────────────────────────────┤
│                              │                                   │
│                    Elasticsearch Client                          │
│                              ▼                                   │
├─────────────────────────────────────────────────────────────────┤
│                     Elasticsearch Cluster                        │
│                    (External: Port 9200)                         │
│         Data Streams: cowrie-*, dionaea-*, galah-*, etc.        │
└─────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Frontend | React + TypeScript | 18.x |
| UI Framework | Tailwind CSS | 3.x |
| Charts | Recharts | 2.x |
| Backend | FastAPI (Python) | 0.100+ |
| Database | Elasticsearch | 8.x |
| Containerization | Docker Compose | - |
| Authentication | JWT Tokens | - |

---

## Backend Implementation

### Directory Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── config.py            # Configuration management (env vars)
│   ├── auth.py              # JWT authentication
│   ├── routers/             # API route handlers
│   │   ├── dashboard.py     # Main dashboard endpoints
│   │   ├── cowrie.py        # Cowrie honeypot endpoints
│   │   ├── dionaea.py       # Dionaea endpoints
│   │   ├── galah.py         # Galah endpoints
│   │   ├── rdpy.py          # RDPY endpoints
│   │   ├── heralding.py     # Heralding endpoints
│   │   ├── firewall.py      # Firewall endpoints
│   │   ├── analytics.py     # Advanced analytics endpoints
│   │   └── attackers.py     # Attacker profiling
│   ├── services/
│   │   ├── elasticsearch.py # Elasticsearch client wrapper
│   │   └── mitre.py         # MITRE ATT&CK mapping
│   └── schemas/
│       └── models.py        # Pydantic response models
├── requirements.txt
└── Dockerfile
```

### Key Backend Components

#### 1. Main Application (`main.py`)

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Honeypot Monitoring API")

# CORS configuration for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(dashboard.router, prefix="/api/dashboard")
app.include_router(cowrie.router, prefix="/api/cowrie")
# ... other routers
```

#### 2. Elasticsearch Service (`services/elasticsearch.py`)

The `ElasticsearchService` class provides a unified interface for querying honeypot data:

```python
class ElasticsearchService:
    # Field mappings for each honeypot (handles schema differences)
    FIELD_MAPPINGS = {
        "cowrie": {
            "src_ip": "json.src_ip",      # Old format
            "src_ip_new": "cowrie.src_ip", # New format
            "session": "json.session",
            "eventid": "json.eventid",
        },
        "dionaea": {
            "src_ip": "source.ip.keyword",
            "geo_country": "source.geo.country_name.keyword",
        },
        # ... other honeypots
    }
    
    async def get_unique_ips(self, index: str, time_range: str) -> int:
        """Get unique source IP count with dual field support."""
        # Aggregates both old and new field structures for compatibility
        
    async def get_timeline(self, index: str, time_range: str) -> List[Dict]:
        """Get event timeline with configurable intervals."""
        
    async def search(self, index: str, query: Dict, aggs: Dict = None) -> Dict:
        """Generic search with aggregations support."""
```

**Key Feature: Dual Field Structure Support**

The cowrie data format changed during development. The service handles both:
- **Old format**: `json.src_ip`, `json.session`, `json.eventid`
- **New format**: `cowrie.src_ip`, `cowrie.session`, `cowrie.eventid`

```python
# Example: Query supporting both formats
query = {
    "bool": {
        "should": [
            {"term": {"json.eventid": "cowrie.command.input"}},
            {"term": {"cowrie.eventid": "cowrie.command.input"}}
        ],
        "minimum_should_match": 1
    }
}
```

#### 3. MITRE ATT&CK Service (`services/mitre.py`)

Maps observed attacker commands to MITRE ATT&CK techniques:

```python
MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    # ... more techniques
}

def categorize_command(command: str) -> Dict:
    """Analyze a command and return categories, techniques, and risk level."""
    # Pattern matching for reconnaissance, execution, exfiltration, etc.
```

#### 4. Router Pattern (`routers/cowrie.py`)

Each honeypot has its own router with standardized endpoints:

```python
@router.get("/stats")
async def get_cowrie_stats(time_range: str = "24h"):
    """Get basic statistics."""
    
@router.get("/timeline")
async def get_cowrie_timeline(time_range: str = "24h"):
    """Get event timeline for charts."""
    
@router.get("/sessions")
async def get_cowrie_sessions(time_range: str = "24h", limit: int = 50):
    """Get session list with details."""
    
@router.get("/variants")
async def get_cowrie_variants(time_range: str = "24h"):
    """Compare Plain vs LLM honeypot variants."""
```

---

## Frontend Implementation

### Directory Structure

```
frontend/
├── src/
│   ├── App.tsx                    # Main app with routing
│   ├── main.tsx                   # Entry point
│   ├── index.css                  # Tailwind imports
│   ├── components/
│   │   ├── Layout.tsx             # Main layout with sidebar
│   │   ├── Card.tsx               # Reusable card component
│   │   ├── DataTable.tsx          # Generic data table
│   │   ├── LoadingSpinner.tsx     # Loading state
│   │   ├── StatsCard.tsx          # KPI display card
│   │   ├── TimeRangeSelector.tsx  # Time range picker
│   │   ├── IPLink.tsx             # IP address with lookup
│   │   └── analytics/             # Analytics-specific components
│   │       ├── FilterBar.tsx
│   │       ├── KPIGrid.tsx
│   │       ├── ExportToolbar.tsx
│   │       └── DateRangePicker.tsx
│   ├── pages/
│   │   ├── Dashboard.tsx          # Main dashboard
│   │   ├── Cowrie.tsx             # Cowrie honeypot page
│   │   ├── Dionaea.tsx            # Dionaea page
│   │   ├── Galah.tsx              # Galah page
│   │   ├── RDPY.tsx               # RDPY page
│   │   ├── Heralding.tsx          # Heralding page
│   │   ├── Firewall.tsx           # Firewall page
│   │   ├── AttackMap.tsx          # Geographic visualization
│   │   ├── Attackers.tsx          # Attacker profiles
│   │   └── analytics/             # Advanced analytics pages
│   │       ├── AnalyticsLayout.tsx
│   │       ├── Overview.tsx
│   │       ├── Commands.tsx
│   │       ├── CaseStudy.tsx
│   │       └── ... (12+ pages)
│   ├── services/
│   │   └── api.ts                 # API client
│   ├── hooks/
│   │   └── useApi.ts              # Data fetching hooks
│   └── types/
│       └── index.ts               # TypeScript interfaces
├── tailwind.config.js
├── vite.config.ts
└── Dockerfile
```

### Key Frontend Components

#### 1. API Service (`services/api.ts`)

Centralized API client with dynamic URL generation for external access:

```typescript
const getApiUrl = (): string => {
  const hostname = window.location.hostname;
  const protocol = window.location.protocol;
  // Dynamically use same hostname with port 8000
  return `${protocol}//${hostname}:8000`;
};

class ApiService {
  private client: AxiosInstance;
  
  constructor() {
    this.client = axios.create({
      baseURL: getApiUrl(),
      headers: { 'Content-Type': 'application/json' },
    });
    
    // JWT token interceptor
    this.client.interceptors.request.use((config) => {
      const token = localStorage.getItem('access_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }
  
  // Generic methods
  getCowrieStats = (timeRange) => this.getHoneypotStats('cowrie', timeRange);
  getCowrieSessions = (timeRange, options) => { /* ... */ };
  
  // Analytics methods
  async getAnalyticsCowrieCommandsTop(timeRange, limit, filters) { /* ... */ }
}
```

#### 2. Data Fetching Hook (`hooks/useApi.ts`)

Custom hook for data fetching with auto-refresh:

```typescript
export function useApiWithRefresh<T>(
  fetcher: () => Promise<T>,
  deps: any[],
  refreshInterval = 60000
): { data: T | null; loading: boolean; error: Error | null; refetch: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchData = async () => {
      try {
        const result = await fetcher();
        setData(result);
      } catch (err) {
        setError(err);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, refreshInterval);
    return () => clearInterval(interval);
  }, deps);
  
  return { data, loading, error, refetch };
}
```

#### 3. Page Component Pattern (`pages/Cowrie.tsx`)

Each honeypot page follows a consistent pattern with tabs:

```tsx
export default function Cowrie() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [activeTab, setActiveTab] = useState('overview');
  
  // Data fetching
  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieStats(timeRange), [timeRange]),
    [timeRange]
  );
  
  const tabs = [
    { id: 'overview', label: 'Overview', icon: <BarChart2 /> },
    { id: 'variants', label: 'Variant Comparison', icon: <GitCompare /> },
    { id: 'credentials', label: 'Credentials', icon: <Key /> },
    { id: 'commands', label: 'Commands', icon: <Terminal /> },
  ];
  
  return (
    <div>
      <PageHeader title="Cowrie SSH Honeypot" />
      <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      <TabNavigation tabs={tabs} active={activeTab} onChange={setActiveTab} />
      
      {activeTab === 'overview' && <OverviewTab data={stats} />}
      {activeTab === 'variants' && <VariantsTab />}
      {/* ... */}
    </div>
  );
}
```

#### 4. Reusable Components

**StatsCard** - KPI display with loading state:
```tsx
<StatsCard
  title="Unique Attackers"
  value={stats?.unique_ips || 0}
  icon={<Users className="w-5 h-5" />}
  color="blue"
  loading={loading}
/>
```

**DataTable** - Generic sortable table:
```tsx
<DataTable
  columns={[
    { key: 'ip', header: 'IP Address', render: (item) => <IPLink ip={item.ip} /> },
    { key: 'count', header: 'Events' },
    { key: 'country', header: 'Country' },
  ]}
  data={attackers}
  loading={loading}
  maxHeight="400px"
/>
```

---

## Data Flow

### Request Flow

```
1. User interacts with UI (e.g., changes time range)
           │
           ▼
2. React component calls API service
   api.getCowrieStats('24h')
           │
           ▼
3. Axios sends HTTP request with JWT
   GET /api/cowrie/stats?time_range=24h
   Authorization: Bearer <token>
           │
           ▼
4. FastAPI router validates request
   - Check JWT token
   - Validate query params
           │
           ▼
5. Router calls Elasticsearch service
   es.get_unique_ips('cowrie-*', '24h')
           │
           ▼
6. Elasticsearch query executed
   - Time range filter
   - Aggregations for counts
   - Both field structures (old/new)
           │
           ▼
7. Response flows back
   { total_events: 131574, unique_ips: 577 }
           │
           ▼
8. React updates UI with new data
```

### Elasticsearch Query Pattern

```json
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-24h" } } },
        {
          "bool": {
            "should": [
              { "term": { "json.eventid": "cowrie.command.input" } },
              { "term": { "cowrie.eventid": "cowrie.command.input" } }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  },
  "aggs": {
    "commands": {
      "terms": { "field": "json.input", "size": 100 },
      "aggs": {
        "unique_ips": { "cardinality": { "field": "json.src_ip" } }
      }
    }
  }
}
```

---

## Key Features

### 1. LLM Honeypot Comparison
Compare effectiveness of Plain vs OpenAI vs Ollama cowrie variants:
- Session duration analysis
- Command execution rates
- Attacker engagement metrics

### 2. MITRE ATT&CK Mapping
Automatic classification of observed commands:
- Technique identification (T1059, T1082, etc.)
- Tactic categorization
- Risk level assessment

### 3. Geographic Attack Visualization
- World map with attack origins
- Country-level statistics
- Suspicious origin detection (VPN/proxy identification)

### 4. Real-time Monitoring
- Auto-refresh every 60 seconds
- Live event timeline
- Attack velocity tracking

### 5. Analytics Dashboard
12+ specialized analytics pages:
- Executive Overview
- Cowrie Sessions Analysis
- Command Sequences (Bigrams)
- Credentials Analysis
- Case Study Builder
- Firewall Correlation

### 6. Export Capabilities
- CSV export for data tables
- PNG/PDF export for charts
- Evidence-ready formatting for thesis

---

## API Design

### Standard Endpoint Pattern

Each honeypot follows consistent API patterns:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/{honeypot}/stats` | GET | Basic statistics |
| `/api/{honeypot}/timeline` | GET | Event timeline |
| `/api/{honeypot}/geo` | GET | Geographic distribution |
| `/api/{honeypot}/top-attackers` | GET | Top attacking IPs |
| `/api/{honeypot}/sessions` | GET | Session list |

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `time_range` | string | `1h`, `24h`, `7d`, `30d` |
| `limit` | int | Max results (default: 50) |
| `variant` | string | Filter by honeypot variant |

### Response Format

```json
{
  "data": [...],
  "time_range": "24h",
  "total": 1234
}
```

---

## Authentication

### JWT-based Authentication

```python
# Backend: auth.py
def create_access_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode = data.copy()
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    return payload.get("sub")
```

```typescript
// Frontend: api.ts
this.client.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

---

## Elasticsearch Integration

### Index Patterns

| Honeypot | Index Pattern | Type |
|----------|---------------|------|
| Cowrie | `.ds-cowrie-*` | Data Stream |
| Dionaea | `dionaea-*` | Regular Index |
| Galah | `.ds-galah-*` | Data Stream |
| RDPY | `rdpy-*` | Regular Index |
| Heralding | `heralding-*` | Regular Index |
| Firewall | `.ds-firewall-*` | Data Stream |

### Field Structure Handling

The system handles evolving data schemas by querying both old and new field locations:

```python
# Support both structures in aggregations
aggs = {
    "unique_ips_old": {"cardinality": {"field": "json.src_ip"}},
    "unique_ips_new": {"cardinality": {"field": "cowrie.src_ip"}}
}

# Combine results
unique_ips = max(
    result["unique_ips_old"]["value"],
    result["unique_ips_new"]["value"]
)
```

---

## Challenges & Solutions

### 1. Data Schema Evolution
**Problem**: Cowrie data format changed from `json.*` to `cowrie.*` namespace.

**Solution**: Implemented dual-field queries using Elasticsearch `should` clauses with `minimum_should_match: 1`.

### 2. External Access / CORS
**Problem**: Frontend couldn't connect when accessed from external IPs.

**Solution**: 
- Dynamic API URL generation using `window.location.hostname`
- Backend CORS configured to allow all origins

### 3. Large Dataset Performance
**Problem**: Aggregations on millions of documents were slow.

**Solution**:
- Use of Elasticsearch aggregations instead of fetching raw documents
- Pagination with reasonable limits
- Time-based filtering to reduce scan scope

### 4. Real-time Updates
**Problem**: Dashboard needed live data without manual refresh.

**Solution**: Custom React hook with configurable auto-refresh interval (60s default).

---

## Deployment

### Docker Compose Configuration

```yaml
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - JWT_SECRET=${JWT_SECRET}
      - CORS_ORIGINS=*
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      
  frontend:
    build: ./frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ELASTICSEARCH_URL` | ES cluster URL | `http://localhost:9200` |
| `JWT_SECRET` | Token signing key | (required) |
| `CORS_ORIGINS` | Allowed origins | `*` |
| `ADMIN_USERNAME` | Default admin user | `admin` |
| `ADMIN_PASSWORD` | Default admin password | (required) |

---

## Conclusion

This honeypot monitoring system provides a comprehensive solution for:
- **Visualization**: Real-time dashboards with charts and maps
- **Analysis**: MITRE ATT&CK mapping, session analysis, command classification
- **Research**: LLM honeypot comparison, case study builder, export capabilities
- **Operations**: Multi-honeypot monitoring, attacker profiling, geographic analysis

The modular architecture allows easy extension for additional honeypot types, and the dual-field support ensures compatibility with evolving data schemas.

---

*Document generated: January 2026*
*System Version: 1.0*

