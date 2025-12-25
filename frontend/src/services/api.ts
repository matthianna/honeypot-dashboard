import axios, { AxiosInstance, AxiosError } from 'axios';
import type {
  LoginRequest,
  TokenResponse,
  DashboardOverview,
  TopAttackersResponse,
  TimelineResponse,
  GeoDistributionResponse,
  StatsResponse,
  AttackEvent,
  AttackMapStats,
  CowrieSession,
  CowrieCredential,
  CowrieCommand,
  CowrieHassh,
  DionaeaProtocolStats,
  DionaeaPortStats,
  DionaeaMalware,
  GalahRequest,
  GalahUserAgent,
  GalahPath,
  RDPYSession,
  RDPYCredential,
  HeraldingCredential,
  HeraldingProtocolStats,
  FirewallBlockedTraffic,
  PortScanDetection,
  RepeatOffender,
  AttackerProfile,
  TimeRange,
} from '../types';

// Dynamically determine API URL based on current location
// If VITE_API_URL is set and we're not on localhost, use it
// Otherwise, use the same hostname with port 8000
const getApiUrl = (): string => {
  const envUrl = import.meta.env.VITE_API_URL;
  const hostname = window.location.hostname;
  
  // If accessing from localhost, always use localhost backend
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:8000';
  }
  
  // If env URL is set, use it
  if (envUrl) {
    return envUrl;
  }
  
  // Default: use same hostname with port 8000
  return `${window.location.protocol}//${hostname}:8000`;
};

const API_URL = getApiUrl();

class ApiService {
  private client: AxiosInstance;
  private refreshPromise: Promise<string> | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('access_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Response interceptor to handle token refresh
    this.client.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const originalRequest = error.config;
        
        if (error.response?.status === 401 && originalRequest && !originalRequest.headers['X-Retry']) {
          try {
            const newToken = await this.refreshToken();
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            originalRequest.headers['X-Retry'] = 'true';
            return this.client(originalRequest);
          } catch {
            // Refresh failed, redirect to login
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.href = '/login';
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  // Auth endpoints
  async login(credentials: LoginRequest): Promise<TokenResponse> {
    const response = await this.client.post<TokenResponse>('/auth/login', credentials);
    localStorage.setItem('access_token', response.data.access_token);
    localStorage.setItem('refresh_token', response.data.refresh_token);
    return response.data;
  }

  async refreshToken(): Promise<string> {
    // Prevent multiple refresh requests
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('No refresh token');
    }

    this.refreshPromise = this.client
      .post<TokenResponse>('/auth/refresh', { refresh_token: refreshToken })
      .then((response) => {
        localStorage.setItem('access_token', response.data.access_token);
        localStorage.setItem('refresh_token', response.data.refresh_token);
        return response.data.access_token;
      })
      .finally(() => {
        this.refreshPromise = null;
      });

    return this.refreshPromise;
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }

  // Dashboard endpoints
  async getDashboardOverview(timeRange: TimeRange = '24h'): Promise<DashboardOverview> {
    const response = await this.client.get<DashboardOverview>('/api/dashboard/overview', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getTopAttackers(timeRange: TimeRange = '24h', limit = 10): Promise<TopAttackersResponse> {
    const response = await this.client.get<TopAttackersResponse>('/api/dashboard/top-attackers', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getDashboardTimeline(timeRange: TimeRange = '24h'): Promise<TimelineResponse> {
    const response = await this.client.get<TimelineResponse>('/api/dashboard/timeline', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGeoStats(timeRange: TimeRange = '24h'): Promise<GeoDistributionResponse> {
    const response = await this.client.get<GeoDistributionResponse>('/api/dashboard/geo-stats', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Alias for map components
  getGeoDistribution = (timeRange: TimeRange = '24h') => this.getGeoStats(timeRange);

  // Get geo distribution for a specific honeypot
  async getHoneypotGeoDistribution(honeypot: string, timeRange: TimeRange = '24h'): Promise<GeoDistributionResponse> {
    const response = await this.client.get<GeoDistributionResponse>(`/api/${honeypot}/geo`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getProtocolDistribution(timeRange: TimeRange = '24h'): Promise<{ time_range: string; protocols: Array<{ protocol: string; count: number }> }> {
    const response = await this.client.get('/api/dashboard/protocol-distribution', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getHourlyHeatmap(timeRange: TimeRange = '7d'): Promise<{ time_range: string; heatmap: Array<{ day: string; day_index: number; hour: number; count: number }> }> {
    const response = await this.client.get('/api/dashboard/hourly-heatmap', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getAttackVelocity(): Promise<{ velocity: Array<{ timestamp: string; count: number }>; stats: { avg_per_minute: number; max_per_minute: number; current_per_minute: number } }> {
    const response = await this.client.get('/api/dashboard/attack-velocity');
    return response.data;
  }

  async getThreatSummary(timeRange: TimeRange = '24h'): Promise<{ time_range: string; summary: Record<string, number> }> {
    const response = await this.client.get('/api/dashboard/threat-summary', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getMitreCoverage(timeRange: TimeRange = '24h'): Promise<{
    time_range: string;
    tactics: Array<{
      tactic: string;
      techniques: Array<{
        id: string;
        name: string;
        tactic: string;
        description: string;
        count: number;
        detected: boolean;
      }>;
    }>;
    summary: {
      techniques_detected: number;
      total_technique_events: number;
      top_techniques: Array<{ id: string; name: string; count: number }>;
    };
  }> {
    const response = await this.client.get('/api/dashboard/mitre-coverage', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getThreatIntel(timeRange: TimeRange = '24h'): Promise<{
    cross_honeypot_actors: Array<{
      ip: string;
      honeypots: string[];
      honeypot_count: number;
      total_events: number;
    }>;
    summary: {
      total_unique_attackers: number;
      multi_honeypot_attackers: number;
      multi_percentage: number;
    };
    honeypot_stats: Record<string, number>;
    time_range: string;
  }> {
    const response = await this.client.get('/api/dashboard/threat-intel', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getTopThreatActors(timeRange: TimeRange = '24h'): Promise<{
    threat_actors: Array<{
      ip: string;
      honeypots: string[];
      honeypot_count: number;
      total_events: number;
      threat_score: number;
      details: Record<string, number>;
    }>;
    total_actors: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/dashboard/top-threat-actors', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Attack Map endpoints
  async getRecentAttacks(limit = 50, honeypot?: string): Promise<AttackEvent[]> {
    const response = await this.client.get<AttackEvent[]>('/api/attackmap/recent', {
      params: { limit, honeypot },
    });
    return response.data;
  }

  async getAttackMapStats(): Promise<AttackMapStats> {
    const response = await this.client.get<AttackMapStats>('/api/attackmap/stats');
    return response.data;
  }

  // Generic honeypot endpoints
  private async getHoneypotStats(honeypot: string, timeRange: TimeRange): Promise<StatsResponse> {
    const response = await this.client.get<StatsResponse>(`/api/${honeypot}/stats`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  private async getHoneypotTimeline(honeypot: string, timeRange: TimeRange): Promise<TimelineResponse> {
    const response = await this.client.get<TimelineResponse>(`/api/${honeypot}/timeline`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  private async getHoneypotGeo(honeypot: string, timeRange: TimeRange): Promise<GeoDistributionResponse> {
    const response = await this.client.get<GeoDistributionResponse>(`/api/${honeypot}/geo`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  private async getHoneypotTopAttackers(honeypot: string, timeRange: TimeRange, limit = 10): Promise<TopAttackersResponse> {
    const response = await this.client.get<TopAttackersResponse>(`/api/${honeypot}/top-attackers`, {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  private async getHoneypotHeatmap(honeypot: string, timeRange: TimeRange): Promise<{ data: Array<{ day: string; hour: number; count: number }> }> {
    const response = await this.client.get(`/api/${honeypot}/heatmap`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Cowrie endpoints
  getCowrieStats = (timeRange: TimeRange) => this.getHoneypotStats('cowrie', timeRange);
  getCowrieTimeline = (timeRange: TimeRange) => this.getHoneypotTimeline('cowrie', timeRange);
  getCowrieGeo = (timeRange: TimeRange) => this.getHoneypotGeo('cowrie', timeRange);
  getCowrieTopAttackers = (timeRange: TimeRange, limit?: number) => this.getHoneypotTopAttackers('cowrie', timeRange, limit);
  getCowrieHeatmap = (timeRange: TimeRange) => this.getHoneypotHeatmap('cowrie', timeRange);

  async getCowrieSessions(timeRange: TimeRange, limit = 50): Promise<CowrieSession[]> {
    const response = await this.client.get<CowrieSession[]>('/api/cowrie/sessions', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getCowrieCredentials(timeRange: TimeRange, limit = 50): Promise<CowrieCredential[]> {
    const response = await this.client.get<CowrieCredential[]>('/api/cowrie/credentials', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getCowrieCommands(timeRange: TimeRange, limit = 50): Promise<CowrieCommand[]> {
    const response = await this.client.get<CowrieCommand[]>('/api/cowrie/commands', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getCowrieHashh(timeRange: TimeRange, limit = 50): Promise<CowrieHassh[]> {
    const response = await this.client.get<CowrieHassh[]>('/api/cowrie/hassh', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getCowrieVariants(timeRange: TimeRange): Promise<{ variants: Array<Record<string, unknown>>; time_range: string }> {
    const response = await this.client.get('/api/cowrie/variants', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieVariantComparison(timeRange: TimeRange): Promise<{ comparison: Array<Record<string, unknown>>; time_range: string }> {
    const response = await this.client.get('/api/cowrie/variant-comparison', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieLoginAnalysis(timeRange: TimeRange): Promise<{ sensors: Array<{ sensor: string; success: number; failed: number; total: number; success_rate: number }>; time_range: string }> {
    const response = await this.client.get('/api/cowrie/login-analysis', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieSessionDurations(timeRange: TimeRange): Promise<{ ranges: Array<{ range: string; count: number }>; stats: { avg_duration: number; max_duration: number; percentiles: Record<string, number> }; time_range: string }> {
    const response = await this.client.get('/api/cowrie/session-durations', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieAttackFunnel(timeRange: TimeRange): Promise<{ funnel: Array<{ stage: string; count: number; percentage: number }>; total_sessions: number; time_range: string }> {
    const response = await this.client.get('/api/cowrie/attack-funnel', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieCredentialReuse(timeRange: TimeRange): Promise<{ top_passwords: Array<{ password: string; count: number }>; top_usernames: Array<{ username: string; count: number }>; unique_sources: number; time_range: string }> {
    const response = await this.client.get('/api/cowrie/credential-reuse', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieClientFingerprints(timeRange: TimeRange): Promise<{
    tools: Array<{ tool: string; count: number }>;
    versions: Array<{ version: string; count: number; tool: string }>;
    fingerprints: Array<{ hassh: string; count: number }>;
    unique_fingerprints: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/cowrie/client-fingerprints', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieWeakAlgorithms(timeRange: TimeRange): Promise<{
    weak_ciphers: Array<{ algorithm: string; count: number; type: string }>;
    weak_kex: Array<{ algorithm: string; count: number; type: string }>;
    weak_mac: Array<{ algorithm: string; count: number; type: string }>;
    summary: {
      total_sessions: number;
      sessions_with_weak: number;
      weak_percentage: number;
      unique_attackers_with_weak: number;
    };
    time_range: string;
  }> {
    const response = await this.client.get('/api/cowrie/weak-algorithms', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieCommandCategories(timeRange: TimeRange): Promise<{
    categories: Array<{ category: string; count: number }>;
    techniques: Array<{ id: string; name: string; tactic: string; count: number }>;
    commands: Array<{ command: string; count: number; categories: string[]; techniques: string[] }>;
    total_commands: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/cowrie/command-categories', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieVariantStats(variant: string, timeRange: TimeRange): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/api/cowrie/variant/${variant}/stats`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCowrieCommandExplorer(timeRange: TimeRange, category?: string): Promise<{
    time_range: string;
    total_executions: number;
    unique_commands: number;
    commands: Array<{
      command: string;
      count: number;
      unique_ips: number;
      sessions: number;
      first_seen: string;
      last_seen: string;
      intent: string;
      description: string;
      mitre: string | null;
      risk: string;
      by_variant: Record<string, number>;
    }>;
    intent_distribution: Array<{ intent: string; count: number; description: string }>;
    risk_distribution: { critical: number; high: number; medium: number; low: number };
    mitre_techniques: Array<{ technique: string; count: number }>;
    variant_totals: Record<string, number>;
    timeline: Array<Record<string, unknown>>;
  }> {
    const response = await this.client.get('/api/cowrie/commands/explorer', {
      params: { time_range: timeRange, category },
    });
    return response.data;
  }

  async getCowrieSessionDetails(sessionId: string): Promise<{
    session_id: string;
    info: {
      src_ip?: string;
      country?: string;
      city?: string;
      sensor?: string;
      protocol?: string;
      start_time?: string;
      end_time?: string;
      duration?: number;
      client_version?: string;
    };
    commands: Array<{ command: string; timestamp: string }>;
    credentials: Array<{ username: string; password: string; success: boolean; timestamp: string }>;
    events: Array<{ type: string; timestamp: string; details: Record<string, unknown> }>;
    total_events: number;
  }> {
    const response = await this.client.get(`/api/cowrie/session/${sessionId}/details`);
    return response.data;
  }

  async getCowrieSessionCommands(sessionId: string): Promise<{
    session_id: string;
    commands: Array<{ command: string; timestamp: string }>;
    total: number;
  }> {
    const response = await this.client.get(`/api/cowrie/session/${sessionId}/commands`);
    return response.data;
  }

  // Dionaea endpoints
  getDionaeaStats = (timeRange: TimeRange) => this.getHoneypotStats('dionaea', timeRange);
  getDionaeaTimeline = (timeRange: TimeRange) => this.getHoneypotTimeline('dionaea', timeRange);
  getDionaeaGeo = (timeRange: TimeRange) => this.getHoneypotGeo('dionaea', timeRange);
  getDionaeaTopAttackers = (timeRange: TimeRange, limit?: number) => this.getHoneypotTopAttackers('dionaea', timeRange, limit);
  getDionaeaHeatmap = (timeRange: TimeRange) => this.getHoneypotHeatmap('dionaea', timeRange);

  async getDionaeaProtocols(timeRange: TimeRange, limit = 20): Promise<DionaeaProtocolStats[]> {
    const response = await this.client.get<DionaeaProtocolStats[]>('/api/dionaea/protocols', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getDionaeaPorts(timeRange: TimeRange, limit = 20): Promise<DionaeaPortStats[]> {
    const response = await this.client.get<DionaeaPortStats[]>('/api/dionaea/ports', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getDionaeaMalware(timeRange: TimeRange, limit = 50): Promise<DionaeaMalware[]> {
    const response = await this.client.get<DionaeaMalware[]>('/api/dionaea/malware', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getDionaeaServiceDistribution(timeRange: TimeRange): Promise<{ services: Array<{ port: number; service: string; count: number; unique_ips: number }>; time_range: string }> {
    const response = await this.client.get('/api/dionaea/service-distribution', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getDionaeaConnectionStates(timeRange: TimeRange): Promise<{ components: Array<{ component: string; count: number }>; avg_duration: number | null; time_range: string }> {
    const response = await this.client.get('/api/dionaea/connection-states', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getDionaeaAttackSources(timeRange: TimeRange): Promise<{ attack_sources: Array<{ port: number; service: string; unique_ips: number; total_connections: number; top_countries: string[] }>; total_unique_ips: number; time_range: string }> {
    const response = await this.client.get('/api/dionaea/attack-sources', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getDionaeaHourlyBreakdown(timeRange: TimeRange): Promise<{ hourly_data: Array<Record<string, unknown>>; time_range: string }> {
    const response = await this.client.get('/api/dionaea/hourly-breakdown', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Galah endpoints
  getGalahStats = (timeRange: TimeRange) => this.getHoneypotStats('galah', timeRange);
  getGalahTimeline = (timeRange: TimeRange) => this.getHoneypotTimeline('galah', timeRange);
  getGalahGeo = (timeRange: TimeRange) => this.getHoneypotGeo('galah', timeRange);
  getGalahTopAttackers = (timeRange: TimeRange, limit?: number) => this.getHoneypotTopAttackers('galah', timeRange, limit);
  getGalahHeatmap = (timeRange: TimeRange) => this.getHoneypotHeatmap('galah', timeRange);

  async getGalahRequests(timeRange: TimeRange, limit = 50): Promise<GalahRequest[]> {
    const response = await this.client.get<GalahRequest[]>('/api/galah/requests', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getGalahUserAgents(timeRange: TimeRange, limit = 50): Promise<GalahUserAgent[]> {
    const response = await this.client.get<GalahUserAgent[]>('/api/galah/user-agents', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getGalahPaths(timeRange: TimeRange, limit = 50): Promise<GalahPath[]> {
    const response = await this.client.get<GalahPath[]>('/api/galah/paths', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getGalahInteractions(timeRange: TimeRange, limit = 50): Promise<{ total: number; interactions: Array<Record<string, unknown>> }> {
    const response = await this.client.get('/api/galah/interactions', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getGalahInteractionPreview(interactionId: string): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/api/galah/interaction/${interactionId}/preview`);
    return response.data;
  }

  async getGalahAIAnalysis(timeRange: TimeRange): Promise<Record<string, unknown>> {
    const response = await this.client.get('/api/galah/ai-analysis', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahAttackPatterns(timeRange: TimeRange): Promise<Record<string, unknown>> {
    const response = await this.client.get('/api/galah/attack-patterns', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahExploitIntelligence(timeRange: TimeRange): Promise<Record<string, unknown>> {
    const response = await this.client.get('/api/galah/exploit-intelligence', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahSessionAnalysis(timeRange: TimeRange): Promise<Record<string, unknown>> {
    const response = await this.client.get('/api/galah/session-analysis', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahSuccessRateTrend(timeRange: TimeRange): Promise<{ trend: Array<{ timestamp: string; success: number; failed: number; total: number; success_rate: number }>; time_range: string }> {
    const response = await this.client.get('/api/galah/success-rate-trend', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahPathCategories(timeRange: TimeRange): Promise<{ categories: Array<{ category: string; count: number; top_paths: Array<{ path: string; count: number }> }>; time_range: string }> {
    const response = await this.client.get('/api/galah/path-categories', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahRequestMethods(timeRange: TimeRange): Promise<{ methods: Array<{ method: string; count: number; success: number; failed: number; success_rate: number }>; time_range: string }> {
    const response = await this.client.get('/api/galah/request-methods', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahSessionDepth(timeRange: TimeRange): Promise<{ distribution: Array<{ depth: string; count: number }>; total_sessions: number; time_range: string }> {
    const response = await this.client.get('/api/galah/session-depth', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahUserAgentAnalysis(timeRange: TimeRange): Promise<{
    browsers: Array<{ name: string; count: number }>;
    operating_systems: Array<{ name: string; count: number }>;
    devices: Array<{ name: string; count: number }>;
    bot_detection: {
      bot_count: number;
      human_count: number;
      bot_percentage: number;
      tools: Array<{ tool: string; count: number }>;
    };
    total_requests: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/galah/user-agent-analysis', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahHttpFingerprints(timeRange: TimeRange): Promise<{
    fingerprints: Array<{ hash: string; full_hash: string; count: number }>;
    protocol_versions: Array<{ version: string; count: number }>;
    header_patterns: Array<{ pattern: string; header_count: number; count: number; scanner_type: string }>;
    unique_fingerprints: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/galah/http-fingerprints', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahLlmStats(timeRange: TimeRange): Promise<{
    summary: {
      total_responses: number;
      llm_generated: number;
      cache_served: number;
      llm_percentage: number;
      cache_hit_rate: number;
    };
    providers: Array<{ provider: string; count: number }>;
    models: Array<{ model: string; count: number }>;
    timeline: Array<{ timestamp: string; llm: number; cache: number }>;
    time_range: string;
  }> {
    const response = await this.client.get('/api/galah/llm-stats', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getGalahContentTypes(timeRange: TimeRange): Promise<{ content_types: Array<{ mime_type: string; count: number }>; time_range: string }> {
    const response = await this.client.get('/api/galah/content-types', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // RDPY endpoints
  getRDPYStats = (timeRange: TimeRange) => this.getHoneypotStats('rdpy', timeRange);
  getRDPYTimeline = (timeRange: TimeRange) => this.getHoneypotTimeline('rdpy', timeRange);
  getRDPYGeo = (timeRange: TimeRange) => this.getHoneypotGeo('rdpy', timeRange);
  getRDPYTopAttackers = (timeRange: TimeRange, limit?: number) => this.getHoneypotTopAttackers('rdpy', timeRange, limit);
  getRDPYHeatmap = (timeRange: TimeRange) => this.getHoneypotHeatmap('rdpy', timeRange);

  async getRDPYSessions(timeRange: TimeRange, limit = 50): Promise<RDPYSession[]> {
    const response = await this.client.get<RDPYSession[]>('/api/rdpy/sessions', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getRDPYCredentials(timeRange: TimeRange, limit = 50): Promise<RDPYCredential[]> {
    const response = await this.client.get<RDPYCredential[]>('/api/rdpy/credentials', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getRDPYConnectionPatterns(timeRange: TimeRange): Promise<{
    repeat_attackers: Array<{
      ip: string;
      connection_count: number;
      first_seen: string;
      last_seen: string;
      active_hours: number;
      intensity: number;
    }>;
    countries: Array<{ country: string; count: number }>;
    summary: {
      total_connections: number;
      unique_sources: number;
      repeat_attacker_count: number;
    };
    time_range: string;
  }> {
    const response = await this.client.get('/api/rdpy/connection-patterns', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getRDPYAttackVelocity(timeRange: TimeRange): Promise<{
    velocity: Array<{ timestamp: string; connections: number; unique_ips: number }>;
    peak_hour: string | null;
    peak_connections: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/rdpy/attack-velocity', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Heralding endpoints
  getHeraldingStats = (timeRange: TimeRange) => this.getHoneypotStats('heralding', timeRange);
  getHeraldingTimeline = (timeRange: TimeRange) => this.getHoneypotTimeline('heralding', timeRange);
  getHeraldingGeo = (timeRange: TimeRange) => this.getHoneypotGeo('heralding', timeRange);
  getHeraldingTopAttackers = (timeRange: TimeRange, limit?: number) => this.getHoneypotTopAttackers('heralding', timeRange, limit);
  getHeraldingHeatmap = (timeRange: TimeRange) => this.getHoneypotHeatmap('heralding', timeRange);

  async getHeraldingCredentials(timeRange: TimeRange, limit = 50, protocol?: string): Promise<HeraldingCredential[]> {
    const response = await this.client.get<HeraldingCredential[]>('/api/heralding/credentials', {
      params: { time_range: timeRange, limit, protocol },
    });
    return response.data;
  }

  async getHeraldingProtocols(timeRange: TimeRange): Promise<HeraldingProtocolStats[]> {
    const response = await this.client.get<HeraldingProtocolStats[]>('/api/heralding/protocols', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getHeraldingProtocolDetailedStats(timeRange: TimeRange): Promise<{ protocols: Array<{ protocol: string; sessions: number; unique_ips: number; avg_duration: number; total_auth_attempts: number; avg_auth_attempts: number; ports: number[] }>; time_range: string }> {
    const response = await this.client.get('/api/heralding/protocol-detailed-stats', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getHeraldingAttemptIntensity(timeRange: TimeRange): Promise<{ intensity: Array<{ timestamp: string; sessions: number; total_attempts: number; avg_attempts: number; unique_ips: number }>; time_range: string }> {
    const response = await this.client.get('/api/heralding/attempt-intensity', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getHeraldingSessionDurationByProtocol(timeRange: TimeRange): Promise<{ protocol_durations: Array<{ protocol: string; sessions: number; min: number; max: number; avg: number; p50: number; p75: number; p90: number }>; time_range: string }> {
    const response = await this.client.get('/api/heralding/session-duration-by-protocol', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getHeraldingCredentialVelocity(timeRange: TimeRange): Promise<{ velocity: Array<{ timestamp: string; attempts: number; rate_per_minute: number }>; total_attempts: number; time_range: string }> {
    const response = await this.client.get('/api/heralding/credential-velocity', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Firewall endpoints
  getFirewallStats = (timeRange: TimeRange) => this.getHoneypotStats('firewall', timeRange);
  getFirewallTimeline = (timeRange: TimeRange) => this.getHoneypotTimeline('firewall', timeRange);
  getFirewallGeo = (timeRange: TimeRange) => this.getHoneypotGeo('firewall', timeRange);
  getFirewallTopAttackers = (timeRange: TimeRange, limit?: number) => this.getHoneypotTopAttackers('firewall', timeRange, limit);
  getFirewallHeatmap = (timeRange: TimeRange) => this.getHoneypotHeatmap('firewall', timeRange);

  async getFirewallBlocked(timeRange: TimeRange, limit = 50): Promise<FirewallBlockedTraffic[]> {
    const response = await this.client.get<FirewallBlockedTraffic[]>('/api/firewall/blocked', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async getPortScans(timeRange: TimeRange, minPorts = 10, limit = 50): Promise<PortScanDetection[]> {
    const response = await this.client.get<PortScanDetection[]>('/api/firewall/port-scans', {
      params: { time_range: timeRange, min_ports: minPorts, limit },
    });
    return response.data;
  }

  async getRepeatOffenders(timeRange: TimeRange, minBlocks = 100, limit = 50): Promise<RepeatOffender[]> {
    const response = await this.client.get<RepeatOffender[]>('/api/firewall/repeat-offenders', {
      params: { time_range: timeRange, min_blocks: minBlocks, limit },
    });
    return response.data;
  }

  async getInternalHostStats(ip: string, timeRange: TimeRange): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/api/firewall/internal-hosts/${ip}`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallEvents(timeRange: TimeRange, limit = 100, action?: string, srcIp?: string, dstIp?: string): Promise<{ total: number; events: Array<Record<string, unknown>> }> {
    const response = await this.client.get('/api/firewall/events', {
      params: { time_range: timeRange, limit, action, src_ip: srcIp, dst_ip: dstIp },
    });
    return response.data;
  }

  async getFirewallActions(timeRange: TimeRange): Promise<{ actions: Array<{ action: string; count: number }> }> {
    const response = await this.client.get('/api/firewall/actions', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallRuleStats(timeRange: TimeRange): Promise<{ rules: Array<{ rule: string; count: number; block_count: number; pass_count: number; unique_sources: number }>; total_rules: number; time_range: string }> {
    const response = await this.client.get('/api/firewall/rule-stats', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallActionTimeline(timeRange: TimeRange): Promise<{ timeline: Array<{ timestamp: string; block: number; pass: number; total: number }>; totals: Record<string, number>; time_range: string }> {
    const response = await this.client.get('/api/firewall/action-timeline', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallDirectionStats(timeRange: TimeRange): Promise<{ directions: Array<{ direction: string; count: number; block_count: number; pass_count: number; unique_sources: number; top_ports: number[] }>; time_range: string }> {
    const response = await this.client.get('/api/firewall/direction-stats', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallTcpFlags(timeRange: TimeRange): Promise<{
    flags: Array<{ flag: string; count: number }>;
    scan_types: Array<{ scan_type: string; count: number }>;
    total_tcp_packets: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/firewall/tcp-flags', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallTtlAnalysis(timeRange: TimeRange): Promise<{
    ttl_distribution: Array<{ ttl: number; count: number; estimated_initial: number; estimated_hops: number; os_guess: string }>;
    os_fingerprints: Array<{ os: string; count: number }>;
    total_packets: number;
    time_range: string;
  }> {
    const response = await this.client.get('/api/firewall/ttl-analysis', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallPacketSizes(timeRange: TimeRange): Promise<{
    histogram: Array<{ range: string; min_size: number; count: number }>;
    stats: { min: number; max: number; avg: number; count: number };
    common_sizes: Array<{ size: string; count: number; meaning: string }>;
    time_range: string;
  }> {
    const response = await this.client.get('/api/firewall/packet-sizes', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getFirewallAttackIntensityHeatmap(timeRange: TimeRange): Promise<{ days: string[]; matrix: number[][]; max_value: number; time_range: string }> {
    const response = await this.client.get('/api/firewall/attack-intensity-heatmap', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  // Attacker profile endpoints
  async getAttackerProfile(ip: string, timeRange: TimeRange = '30d'): Promise<AttackerProfile> {
    const response = await this.client.get<AttackerProfile>(`/api/attacker/${ip}`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getAttackerTimeline(ip: string, timeRange: TimeRange = '30d', limit = 100): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/api/attacker/${ip}/timeline`, {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  async exportAttackerData(ip: string, format: 'json' | 'csv' = 'json', timeRange: TimeRange = '30d'): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/api/attacker/${ip}/export`, {
      params: { format, time_range: timeRange },
    });
    return response.data;
  }

  // Country-based attacker endpoints
  async getAttackersByCountry(timeRange: TimeRange = '24h'): Promise<{
    time_range: string;
    countries: Array<{
      country: string;
      total_events: number;
      unique_ips: number;
      honeypots: Record<string, { events: number; ips: number; color: string }>;
    }>;
    total_countries: number;
  }> {
    const response = await this.client.get('/api/attacker/countries/list', {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getCountryAttackers(countryName: string, timeRange: TimeRange = '24h'): Promise<{
    country: string;
    time_range: string;
    attackers: Array<{
      ip: string;
      country: string;
      city: string | null;
      total_events: number;
      first_seen: string;
      last_seen: string;
      honeypots_attacked: string[];
      honeypot_details: Record<string, { events: number; color: string }>;
    }>;
    total_attackers: number;
    total_events: number;
  }> {
    const response = await this.client.get(`/api/attacker/countries/${encodeURIComponent(countryName)}/attackers`, {
      params: { time_range: timeRange },
    });
    return response.data;
  }

  async getTopAttackersList(timeRange: TimeRange = '24h', limit = 50): Promise<{
    time_range: string;
    attackers: Array<{
      ip: string;
      country: string;
      total_events: number;
      honeypots: string[];
      first_seen: string;
      last_seen: string;
    }>;
    total: number;
  }> {
    const response = await this.client.get('/api/attacker/top/list', {
      params: { time_range: timeRange, limit },
    });
    return response.data;
  }

  // WebSocket connection for attack map
  createAttackMapWebSocket(): WebSocket {
    const wsUrl = API_URL.replace('http', 'ws') + '/api/attackmap/ws';
    return new WebSocket(wsUrl);
  }
}

export const api = new ApiService();
export default api;

