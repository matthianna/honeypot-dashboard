// Authentication types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface User {
  username: string;
}

// Common types
export interface TimelinePoint {
  timestamp: string;
  count: number;
}

export interface GeoPoint {
  country: string;
  count: number;
}

export interface TopAttacker {
  ip: string;
  count: number;
  country?: string;
  city?: string;
  // Duration metrics for human vs script detection
  total_duration_seconds?: number;
  avg_session_duration?: number;
  session_count?: number;
  behavior_classification?: 'Script' | 'Human' | 'Bot';
}

// Dashboard types
export interface HoneypotStats {
  name: string;
  total_events: number;
  unique_ips: number;
  color: string;
}

export interface DashboardOverview {
  honeypots: HoneypotStats[];
  total_events: number;
  total_unique_ips: number;
  time_range: string;
}

// Attack Map types
export interface AttackEvent {
  id: string;
  timestamp: string;
  honeypot: 'cowrie' | 'dionaea' | 'galah' | 'rdpy' | 'heralding' | 'firewall';
  src_ip: string;
  src_lat?: number;
  src_lon?: number;
  src_country?: string;
  dst_ip?: string;
  dst_lat?: number;
  dst_lon?: number;
  protocol?: string;
  port?: number;
}

export interface AttackMapStats {
  total_attacks: number;
  unique_ips: number;
  countries: number;
}

// Cowrie types
export interface CowrieSession {
  session_id: string;
  src_ip: string;
  start_time: string;
  end_time?: string;
  duration?: number;
  commands_count: number;
  country?: string;
}

export interface CowrieCredential {
  username: string;
  password: string;
  count: number;
  success: boolean;
}

export interface CowrieCommand {
  command: string;
  count: number;
}

export interface CowrieHassh {
  hassh: string;
  count: number;
  client_version?: string;
}

export interface CowrieVariantStats {
  variant: string;
  total_events: number;
  unique_ips: number;
  avg_session_duration?: number;
  unique_commands: number;
}

// Dionaea types
export interface DionaeaProtocolStats {
  protocol: string;
  count: number;
}

export interface DionaeaPortStats {
  port: number;
  count: number;
  protocol?: string;
}

export interface DionaeaMalware {
  md5: string;
  count: number;
  first_seen?: string;
}

// Galah types
export interface GalahRequest {
  method: string;
  uri: string;
  count: number;
}

export interface GalahUserAgent {
  user_agent: string;
  count: number;
}

export interface GalahPath {
  path: string;
  count: number;
  methods: string[];
}

// RDPY types
export interface RDPYSession {
  session_id: string;
  src_ip: string;
  username?: string;
  domain?: string;
  timestamp: string;
  country?: string;
}

export interface RDPYCredential {
  username: string;
  domain?: string;
  count: number;
}

// Heralding types
export interface HeraldingCredential {
  protocol: string;
  username: string;
  password: string;
  count: number;
}

export interface HeraldingProtocolStats {
  protocol: string;
  count: number;
  unique_ips: number;
}

// Firewall types
export interface FirewallBlockedTraffic {
  src_ip: string;
  count: number;
  ports: number[];
  protocols: string[];
  country?: string;
}

export interface PortScanDetection {
  src_ip: string;
  unique_ports: number;
  time_window: string;
  first_seen: string;
  last_seen: string;
  country?: string;
}

export interface RepeatOffender {
  src_ip: string;
  total_blocks: number;
  first_seen: string;
  last_seen: string;
  targeted_ports: number[];
  country?: string;
}

// Attacker profile types
export interface HoneypotActivity {
  honeypot: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
  duration_seconds?: number;
  session_count?: number;
}

export interface AttackerProfile {
  ip: string;
  total_events: number;
  first_seen: string;
  last_seen: string;
  countries: string[];
  honeypot_activity: HoneypotActivity[];
  credentials_tried?: CowrieCredential[];
  commands_executed?: string[];
  // Duration metrics for human vs script detection
  total_duration_seconds?: number;
  avg_session_duration?: number;
  session_count?: number;
  behavior_classification?: 'Script' | 'Human' | 'Bot';
}

// Heatmap types
export interface HeatmapPoint {
  day: string;
  hour: number;
  count: number;
}

// API Response types
export interface StatsResponse {
  total_events: number;
  unique_ips: number;
  time_range: string;
}

export interface TimelineResponse {
  data: TimelinePoint[];
  time_range: string;
}

export interface GeoDistributionResponse {
  data: GeoPoint[];
  time_range: string;
}

export interface TopAttackersResponse {
  data: TopAttacker[];
  time_range: string;
}

// Time range type
export type TimeRange = '1h' | '24h' | '7d' | '30d';

// Honeypot type
export type HoneypotType = 'cowrie' | 'dionaea' | 'galah' | 'rdpy' | 'heralding' | 'firewall';

// Honeypot colors
export const HONEYPOT_COLORS: Record<HoneypotType, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
  firewall: '#ffff00',
};

// Honeypot names
export const HONEYPOT_NAMES: Record<HoneypotType, string> = {
  cowrie: 'Cowrie (SSH)',
  dionaea: 'Dionaea',
  galah: 'Galah (Web)',
  rdpy: 'RDPY (RDP)',
  heralding: 'Heralding',
  firewall: 'Firewall',
};

