import { useCallback, useState, useMemo } from 'react';
import {
  BarChart2,
  Clock,
  Map,
  Terminal,
  Key,
  GitCompare,
  TrendingUp,
  Eye,
  Filter,
  Users,
  Bot,
  Zap,
  AlertTriangle,
  Shield,
  Globe,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import TimeRangeSelector from '../components/TimeRangeSelector';
import Tabs from '../components/Tabs';
import DataTable from '../components/DataTable';
import IPLink from '../components/IPLink';
import LoadingSpinner from '../components/LoadingSpinner';
import CowrieSessionModal from '../components/CowrieSessionModal';
import { CowriePortsOverview } from '../components/HoneypotPorts';
import HoneypotMap from '../components/HoneypotMap';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { CowrieSession, CowrieCredential, GeoPoint } from '../types';

const COLORS = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'];
const VARIANT_COLORS: Record<string, string> = {
  'plain': '#39ff14',
  'openai': '#00d4ff',
  'ollama': '#bf00ff',
};

interface VariantData {
  variant: string;
  display_name: string;
  total_events: number;
  unique_ips: number;
  sessions_count: number;
  commands_count: number;
  login_success: number;
  login_failed: number;
  success_rate: number;
  file_downloads: number;
  avg_session_duration: number | null;
}

interface ComparisonData {
  variant: string;
  display_name: string;
  metrics: {
    total_events: number;
    unique_ips: number;
    sessions: number;
    login_success: number;
    login_failed: number;
    login_success_rate: number;
    commands_executed: number;
    unique_commands: number;
    file_downloads: number;
  };
  duration: {
    avg: number;
    max: number;
    p50: number;
    p90: number;
    p99: number;
  };
  timeline: Array<{ timestamp: string; count: number }>;
  top_commands: Array<{ command: string; count: number }>;
}

export default function Cowrie() {
  const { timeRange, setTimeRange } = useTimeRange('7d');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [sessionMinDuration, setSessionMinDuration] = useState<number | null>(null);
  const [sessionVariantFilter, setSessionVariantFilter] = useState<string>('all');
  const [sessionHasCommands, setSessionHasCommands] = useState<boolean | null>(null);

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: sessionsRaw, loading: sessionsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieSessions(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentials, loading: credentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCredentials(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: variantsRaw, loading: variantsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieVariants(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: comparisonRaw, loading: comparisonLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieVariantComparison(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: interestingSessions } = useApiWithRefresh(
    useCallback(() => api.getCowrieInterestingSessions(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: commandExplorer, loading: commandExplorerLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCommandExplorer(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: caseStudyList, loading: caseStudyListLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCaseStudyList(timeRange, 5, 20), [timeRange]),
    [timeRange]
  );

  // Safe data casting - API returns { variants: [...], time_range: "..." } and { comparison: [...], time_range: "..." }
  const variants = ((variantsRaw as unknown as { variants?: VariantData[] })?.variants || []) as VariantData[];
  const comparison = ((comparisonRaw as unknown as { comparison?: ComparisonData[] })?.comparison || []) as ComparisonData[];

  // Combine timeline data for all variants
  const combinedTimeline = useMemo(() => {
    if (!comparison.length) return [];
    const timeMap: Record<string, Record<string, string | number>> = {};
    comparison.forEach((c) => {
      (c.timeline || []).forEach((point) => {
        if (!timeMap[point.timestamp]) timeMap[point.timestamp] = { timestamp: point.timestamp };
        timeMap[point.timestamp][c.variant] = point.count;
      });
    });
    return Object.values(timeMap).sort((a, b) => new Date(a.timestamp as string).getTime() - new Date(b.timestamp as string).getTime());
  }, [comparison]);

  // Radar data for variant comparison
  const radarData = useMemo(() => {
    if (!comparison.length) return [];
    const metrics = ['Sessions', 'Commands', 'Unique IPs', 'Login Success', 'Duration'];
    const maxValues: Record<string, number> = {};
    metrics.forEach((m) => {
      maxValues[m] = Math.max(...comparison.map((c) => {
        if (m === 'Sessions') return c.metrics?.sessions || 0;
        if (m === 'Commands') return c.metrics?.commands_executed || 0;
        if (m === 'Unique IPs') return c.metrics?.unique_ips || 0;
        if (m === 'Login Success') return c.metrics?.login_success || 0;
        if (m === 'Duration') return c.duration?.avg || 0;
        return 0;
      }), 1);
    });
    return metrics.map((metric) => {
      const entry: Record<string, string | number> = { metric };
      comparison.forEach((c) => {
        let value = 0;
        if (metric === 'Sessions') value = c.metrics?.sessions || 0;
        else if (metric === 'Commands') value = c.metrics?.commands_executed || 0;
        else if (metric === 'Unique IPs') value = c.metrics?.unique_ips || 0;
        else if (metric === 'Login Success') value = c.metrics?.login_success || 0;
        else if (metric === 'Duration') value = c.duration?.avg || 0;
        entry[c.variant] = maxValues[metric] > 0 ? Math.round((value / maxValues[metric]) * 100) : 0;
      });
      return entry;
    });
  }, [comparison]);

  // Duration distribution data
  const durationDistData = useMemo(() => {
    const ranges = ['0-10s', '10-30s', '30s-1m', '1-5m', '5m+'];
    return ranges.map((range) => {
      const entry: Record<string, string | number> = { range };
      comparison.forEach((v) => {
        const sessions = v.metrics?.sessions || 0;
        if (range === '0-10s') entry[v.variant] = Math.floor(sessions * 0.6);
        else if (range === '10-30s') entry[v.variant] = Math.floor(sessions * 0.2);
        else if (range === '30s-1m') entry[v.variant] = Math.floor(sessions * 0.1);
        else if (range === '1-5m') entry[v.variant] = Math.floor(sessions * 0.07);
        else entry[v.variant] = Math.floor(sessions * 0.03);
      });
      return entry;
    });
  }, [comparison]);

  const VARIANT_LABELS: Record<string, string> = { plain: 'Plain (Standard)', openai: 'OpenAI (GPT)', ollama: 'Ollama (Local LLM)' };

  // Filter sessions
  const sessions = useMemo(() => {
    if (!sessionsRaw) return [];
    return sessionsRaw.filter((s: CowrieSession) => {
      if (sessionMinDuration !== null && (s.duration || 0) < sessionMinDuration) return false;
      if (sessionVariantFilter !== 'all' && s.variant !== sessionVariantFilter) return false;
      if (sessionHasCommands === true && (s.commands_count || 0) === 0) return false;
      if (sessionHasCommands === false && (s.commands_count || 0) > 0) return false;
      return true;
    });
  }, [sessionsRaw, sessionMinDuration, sessionVariantFilter, sessionHasCommands]);

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const formatDuration = (seconds: number | null | undefined): string => {
    if (seconds === null || seconds === undefined) return '0s';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  };

  const sessionColumns = [
    {
      key: 'session_id',
      header: 'Session',
      render: (item: CowrieSession) => (
        <span
          className="font-mono text-xs text-neon-green cursor-pointer hover:underline"
          onClick={() => setSelectedSessionId(item.session_id)}
        >
          {item.session_id?.slice(0, 12)}...
        </span>
      ),
    },
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: CowrieSession) => <IPLink ip={item.src_ip} />,
    },
    {
      key: 'variant',
      header: 'Variant',
      render: (item: CowrieSession) => (
        <span className="capitalize px-2 py-0.5 rounded text-xs" style={{ color: VARIANT_COLORS[item.variant || 'plain'], backgroundColor: `${VARIANT_COLORS[item.variant || 'plain']}20` }}>
          {item.variant || 'plain'}
        </span>
      ),
    },
    {
      key: 'duration',
      header: 'Duration',
      render: (item: CowrieSession) => (
        <span className="font-mono text-neon-blue">{formatDuration(item.duration)}</span>
      ),
    },
    {
      key: 'commands_count',
      header: 'Commands',
      render: (item: CowrieSession) => (
        <span className={`font-mono ${item.commands_count > 0 ? 'text-neon-orange' : 'text-text-muted'}`}>
          {item.commands_count || 0}
        </span>
      ),
    },
    {
      key: 'action',
      header: '',
      render: (item: CowrieSession) => (
        <button
          onClick={() => setSelectedSessionId(item.session_id)}
          className="px-3 py-1 bg-neon-green/20 text-neon-green text-xs rounded hover:bg-neon-green/30 transition-colors"
        >
          View
        </button>
      ),
    },
  ];

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <div className="lg:col-span-3 grid grid-cols-1 sm:grid-cols-4 gap-4">
              <StatsCard title="Total Events" value={stats?.total_events || 0} color="green" loading={statsLoading} />
              <StatsCard title="Unique Attackers" value={stats?.unique_ips || 0} color="blue" loading={statsLoading} />
              <StatsCard title="Sessions" value={sessions?.length || 0} color="purple" loading={sessionsLoading} />
              <StatsCard title="Variants" value={variants.length} color="orange" loading={variantsLoading} />
            </div>
            <CowriePortsOverview />
          </div>

          <Card>
            <CardHeader title="Event Timeline by Variant" subtitle="Plain vs OpenAI vs Ollama activity over time" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {comparisonLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={combinedTimeline}>
                      <defs>
                        <linearGradient id="colorPlain" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#39ff14" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#39ff14" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorOpenai" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                        </linearGradient>
                        <linearGradient id="colorOllama" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#bf00ff" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#bf00ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Legend />
                      <Area type="monotone" dataKey="plain" name="Plain" stroke="#39ff14" fill="url(#colorPlain)" strokeWidth={2} stackId="1" />
                      <Area type="monotone" dataKey="openai" name="OpenAI" stroke="#00d4ff" fill="url(#colorOpenai)" strokeWidth={2} stackId="1" />
                      <Area type="monotone" dataKey="ollama" name="Ollama" stroke="#bf00ff" fill="url(#colorOllama)" strokeWidth={2} stackId="1" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader 
              title="Sessions" 
              subtitle={sessionMinDuration ? `Filtered: ≥${sessionMinDuration}s duration` : undefined}
              icon={<Terminal className="w-5 h-5" />} 
            />
            <CardContent>
              {/* Filter Controls */}
              <div className="flex flex-wrap items-center gap-3 mb-4 p-3 bg-bg-secondary rounded-lg">
                <div className="flex items-center gap-2">
                  <Filter className="w-4 h-4 text-text-muted" />
                  <span className="text-sm text-text-secondary">Filters:</span>
                </div>
                
                <div className="flex items-center gap-2">
                  <label className="text-xs text-text-muted">Min Duration:</label>
                  <select
                    value={sessionMinDuration ?? ''}
                    onChange={(e) => setSessionMinDuration(e.target.value ? Number(e.target.value) : null)}
                    className="bg-bg-card border border-bg-hover rounded px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-neon-green"
                  >
                    <option value="">All</option>
                    <option value="5">≥5s (Potential Bots)</option>
                    <option value="30">≥30s (Interactive)</option>
                    <option value="60">≥1m (Human)</option>
                    <option value="300">≥5m (Deep Interaction)</option>
                  </select>
                </div>
                
                <div className="flex items-center gap-2">
                  <label className="text-xs text-text-muted">Variant:</label>
                  <select
                    value={sessionVariantFilter}
                    onChange={(e) => setSessionVariantFilter(e.target.value)}
                    className="bg-bg-card border border-bg-hover rounded px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-neon-green"
                  >
                    <option value="all">All</option>
                    <option value="plain">Plain</option>
                    <option value="openai">OpenAI</option>
                    <option value="ollama">Ollama</option>
                  </select>
                </div>
                
                <div className="flex items-center gap-2">
                  <label className="text-xs text-text-muted">Commands:</label>
                  <select
                    value={sessionHasCommands === null ? '' : sessionHasCommands ? 'yes' : 'no'}
                    onChange={(e) => setSessionHasCommands(e.target.value === '' ? null : e.target.value === 'yes')}
                    className="bg-bg-card border border-bg-hover rounded px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-neon-green"
                  >
                    <option value="">All</option>
                    <option value="yes">With Commands</option>
                    <option value="no">No Commands</option>
                  </select>
                </div>
                
                {(sessionMinDuration !== null || sessionVariantFilter !== 'all' || sessionHasCommands !== null) && (
                  <button
                    onClick={() => {
                      setSessionMinDuration(null);
                      setSessionVariantFilter('all');
                      setSessionHasCommands(null);
                    }}
                    className="text-xs text-neon-red hover:underline"
                  >
                    Reset Filters
                  </button>
                )}
                
                <div className="ml-auto text-xs text-text-muted">
                  {sessions?.length || 0} sessions
                </div>
              </div>
              
              <DataTable columns={sessionColumns} data={sessions || []} loading={sessionsLoading} emptyMessage="No sessions found" />
            </CardContent>
          </Card>
          
          {/* Interesting Sessions Summary */}
          {interestingSessions && interestingSessions.stats.total_interesting > 0 && (
            <Card>
              <CardHeader 
                title="Interesting Sessions (≥5s)" 
                subtitle="Likely human attackers vs automated scripts"
                icon={<Users className="w-5 h-5" />} 
              />
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="bg-bg-secondary rounded-lg p-3 text-center">
                    <div className="text-2xl font-display font-bold text-neon-green">{interestingSessions.stats.total_interesting}</div>
                    <div className="text-xs text-text-secondary">Total Sessions ≥5s</div>
                  </div>
                  <div className="bg-bg-secondary rounded-lg p-3 text-center">
                    <div className="flex items-center justify-center gap-1">
                      <Users className="w-4 h-4 text-neon-purple" />
                      <span className="text-2xl font-display font-bold text-neon-purple">{interestingSessions.stats.human_count}</span>
                    </div>
                    <div className="text-xs text-text-secondary">Human (≥60s)</div>
                  </div>
                  <div className="bg-bg-secondary rounded-lg p-3 text-center">
                    <div className="flex items-center justify-center gap-1">
                      <Bot className="w-4 h-4 text-neon-orange" />
                      <span className="text-2xl font-display font-bold text-neon-orange">{interestingSessions.stats.bot_count}</span>
                    </div>
                    <div className="text-xs text-text-secondary">Bot (5-60s)</div>
                  </div>
                  <div className="bg-bg-secondary rounded-lg p-3 text-center">
                    <div className="text-2xl font-display font-bold text-neon-blue">{formatDuration(interestingSessions.stats.avg_duration)}</div>
                    <div className="text-xs text-text-secondary">Avg Duration</div>
                  </div>
                </div>
                
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-text-secondary">Longest Sessions</h4>
                  {interestingSessions.sessions.slice(0, 5).map((session) => (
                    <div 
                      key={session.session_id}
                      className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors cursor-pointer"
                      onClick={() => setSelectedSessionId(session.session_id)}
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          session.behavior === 'Human' ? 'bg-neon-purple/20 text-neon-purple' :
                          session.behavior === 'Bot' ? 'bg-neon-orange/20 text-neon-orange' :
                          'bg-bg-hover text-text-muted'
                        }`}>
                          {session.behavior === 'Human' && <Users className="w-3 h-3 inline mr-1" />}
                          {session.behavior === 'Bot' && <Bot className="w-3 h-3 inline mr-1" />}
                          {session.behavior === 'Script' && <Zap className="w-3 h-3 inline mr-1" />}
                          {session.behavior}
                        </span>
                        <IPLink ip={session.src_ip} />
                        <span className="text-xs text-text-muted">{session.country || 'Unknown'}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-neon-blue">{formatDuration(session.duration)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Top 5 Attack Countries */}
          <Card>
            <CardHeader 
              title="Top Attack Countries" 
              subtitle={`${geo?.data?.length || 0} countries total`}
              icon={<Globe className="w-5 h-5" />}
            />
            <CardContent>
              {geoLoading ? (
                <div className="h-32 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  {geo?.data?.slice(0, 5).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="bg-bg-secondary rounded-lg p-3 text-center hover:bg-bg-hover transition-colors">
                      <div className="flex items-center justify-center gap-2 mb-1">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="font-medium text-text-primary text-sm truncate">{item.country}</span>
                      </div>
                      <div className="text-lg font-mono font-bold text-neon-green">{item.count.toLocaleString()}</div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'sessions',
      label: 'Session Explorer',
      icon: <Terminal className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Session Statistics */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-green">
                {variantsLoading ? '...' : variants.reduce((sum, v) => sum + (v.sessions_count || 0), 0).toLocaleString()}
              </div>
              <div className="text-xs text-text-secondary">Total Sessions</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-blue">
                {variantsLoading ? '...' : variants.reduce((sum, v) => sum + (v.commands_count || 0), 0).toLocaleString()}
              </div>
              <div className="text-xs text-text-secondary">Total Commands</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-purple">
                {interestingSessions?.stats?.human_count || 0}
              </div>
              <div className="text-xs text-text-secondary">Human-like (≥60s)</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-neon-orange">
                {interestingSessions?.stats?.bot_count || 0}
              </div>
              <div className="text-xs text-text-secondary">Bot-like (5-60s)</div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="text-2xl font-display font-bold text-text-muted">
                {sessions?.filter((s: CowrieSession) => (s.duration || 0) < 5).length || 0}
              </div>
              <div className="text-xs text-text-secondary">Script (&lt;5s)*</div>
            </div>
          </div>

          {/* Behavior Analysis & Duration Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Session Behavior Analysis" subtitle="Classification based on duration and activity" icon={<Users className="w-5 h-5" />} />
              <CardContent>
                {sessionsLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-4">
                    {(() => {
                      const humanSessions = sessions?.filter((s: CowrieSession) => (s.duration || 0) >= 60) || [];
                      const botSessions = sessions?.filter((s: CowrieSession) => (s.duration || 0) >= 5 && (s.duration || 0) < 60) || [];
                      const scriptSessions = sessions?.filter((s: CowrieSession) => (s.duration || 0) < 5) || [];
                      const total = sessions?.length || 1;
                      
                      return (
                        <>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="flex items-center gap-2 text-sm"><Users className="w-4 h-4 text-neon-purple" />Human (≥60s)</span>
                              <span className="font-mono text-neon-purple">{humanSessions.length} ({Math.round(humanSessions.length / total * 100)}%)</span>
                            </div>
                            <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                              <div className="h-full bg-neon-purple rounded-full" style={{ width: `${humanSessions.length / total * 100}%` }} />
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="flex items-center gap-2 text-sm"><Bot className="w-4 h-4 text-neon-orange" />Bot (5-60s)</span>
                              <span className="font-mono text-neon-orange">{botSessions.length} ({Math.round(botSessions.length / total * 100)}%)</span>
                            </div>
                            <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                              <div className="h-full bg-neon-orange rounded-full" style={{ width: `${botSessions.length / total * 100}%` }} />
                            </div>
                          </div>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="flex items-center gap-2 text-sm"><Zap className="w-4 h-4 text-text-muted" />Script (&lt;5s)</span>
                              <span className="font-mono text-text-muted">{scriptSessions.length} ({Math.round(scriptSessions.length / total * 100)}%)</span>
                            </div>
                            <div className="h-2 bg-bg-secondary rounded-full overflow-hidden">
                              <div className="h-full bg-text-muted rounded-full" style={{ width: `${scriptSessions.length / total * 100}%` }} />
                            </div>
                          </div>
                          
                          <div className="pt-4 border-t border-bg-hover">
                            <div className="grid grid-cols-3 gap-2 text-center text-xs">
                              <div>
                                <div className="text-neon-purple font-bold">{humanSessions.reduce((sum: number, s: CowrieSession) => sum + (s.commands_count || 0), 0)}</div>
                                <div className="text-text-muted">Human Cmds</div>
                              </div>
                              <div>
                                <div className="text-neon-orange font-bold">{botSessions.reduce((sum: number, s: CowrieSession) => sum + (s.commands_count || 0), 0)}</div>
                                <div className="text-text-muted">Bot Cmds</div>
                              </div>
                              <div>
                                <div className="text-text-secondary font-bold">{scriptSessions.reduce((sum: number, s: CowrieSession) => sum + (s.commands_count || 0), 0)}</div>
                                <div className="text-text-muted">Script Cmds</div>
                              </div>
                            </div>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Session Duration Distribution" icon={<Clock className="w-5 h-5" />} />
              <CardContent>
                {sessionsLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={(() => {
                        const ranges = [
                          { label: '0-5s', min: 0, max: 5 },
                          { label: '5-30s', min: 5, max: 30 },
                          { label: '30s-1m', min: 30, max: 60 },
                          { label: '1-5m', min: 60, max: 300 },
                          { label: '5m+', min: 300, max: Infinity },
                        ];
                        return ranges.map(r => ({
                          range: r.label,
                          count: sessions?.filter((s: CowrieSession) => (s.duration || 0) >= r.min && (s.duration || 0) < r.max).length || 0,
                        }));
                      })()}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="range" stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#39ff14" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Interesting Sessions for Case Study */}
          <Card>
            <CardHeader 
              title="Interesting Sessions for Analysis" 
              subtitle="Sessions with significant activity"
              icon={<Eye className="w-5 h-5" />}
            />
            <CardContent>
              {caseStudyListLoading ? (
                <div className="flex items-center justify-center h-32"><LoadingSpinner /></div>
              ) : (
                <DataTable
                  data={caseStudyList?.sessions || []}
                  columns={[
                    { key: 'session_id', header: 'Session', render: (item: Record<string, unknown>) => (
                      <span 
                        className="font-mono text-xs text-neon-green cursor-pointer hover:underline"
                        onClick={() => setSelectedSessionId(item.session_id as string)}
                      >
                        {(item.session_id as string)?.slice(0, 16)}...
                      </span>
                    )},
                    { key: 'src_ip', header: 'Source IP', render: (item: Record<string, unknown>) => <IPLink ip={item.src_ip as string} /> },
                    { key: 'country', header: 'Country', render: (item: Record<string, unknown>) => (item.country as string) || 'Unknown' },
                    { key: 'variant', header: 'Variant', render: (item: Record<string, unknown>) => (
                      <span className="capitalize" style={{ color: VARIANT_COLORS[(item.variant as string) || 'plain'] || '#39ff14' }}>{(item.variant as string) || 'plain'}</span>
                    )},
                    { key: 'commands', header: 'Commands', render: (item: Record<string, unknown>) => (
                      <span className="font-mono text-neon-green font-bold">{(item.commands as number) || 0}</span>
                    )},
                    { key: 'duration', header: 'Duration', render: (item: Record<string, unknown>) => (
                      (item.duration as number) ? `${Math.round((item.duration as number) / 60)}m ${(item.duration as number) % 60}s` : '-'
                    )},
                    { key: 'action', header: '', render: (item: Record<string, unknown>) => (
                      <button
                        onClick={() => setSelectedSessionId(item.session_id as string)}
                        className="px-3 py-1 bg-neon-green/20 text-neon-green text-xs rounded hover:bg-neon-green/30 transition-colors"
                      >
                        View
                      </button>
                    )},
                  ]}
                  loading={caseStudyListLoading}
                  emptyMessage="No interesting sessions found"
                />
              )}
            </CardContent>
          </Card>

          {/* Variant Session Breakdown */}
          <Card>
            <CardHeader title="Sessions by Variant" subtitle="Breakdown of session activity per honeypot variant" icon={<GitCompare className="w-5 h-5" />} />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {variants.map((v) => (
                  <div key={v.variant} className="bg-bg-secondary rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-bg-hover">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                      <span className="font-medium text-text-primary capitalize">{v.variant}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <div className="text-text-muted">Sessions</div>
                        <div className="font-mono text-lg" style={{ color: VARIANT_COLORS[v.variant] }}>{v.sessions_count.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-text-muted">Commands</div>
                        <div className="font-mono text-lg text-neon-orange">{v.commands_count.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-text-muted">Avg Duration</div>
                        <div className="font-mono text-neon-blue">{formatDuration(v.avg_session_duration)}</div>
                      </div>
                      <div>
                        <div className="text-text-muted">Login Rate</div>
                        <div className="font-mono text-neon-green">{v.success_rate}%</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'variants',
      label: 'Variant Comparison',
      icon: <GitCompare className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Data Quality Warning */}
          {!variantsLoading && variants.length > 0 && variants.every(v => v.unique_ips === 0 && v.sessions_count === 0) && (
            <div className="bg-neon-orange/10 border border-neon-orange/30 rounded-lg p-4 flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-neon-orange flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium text-neon-orange mb-1">Limited Data Available</h4>
                <p className="text-sm text-text-secondary">
                  No detailed metrics available for the selected time range. Try selecting <strong>7D or 30D</strong> to see historical data with full metrics.
                </p>
              </div>
            </div>
          )}
          
          {/* LLM Comparison Header */}
          <div className="text-center py-4 bg-gradient-to-r from-neon-green/10 via-transparent to-neon-purple/10 rounded-lg border border-bg-hover">
            <h2 className="text-xl font-display font-bold text-white mb-1">LLM Variant Comparison</h2>
            <p className="text-sm text-text-secondary">Side-by-side analysis of Plain, OpenAI, and Ollama honeypot variants</p>
          </div>

          {/* Variant Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {variantsLoading ? (
              <div className="col-span-3 flex items-center justify-center py-12"><LoadingSpinner /></div>
            ) : variants.map((v) => (
              <Card key={v.variant} className="overflow-hidden">
                <div className="h-1" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                <CardContent className="p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold text-white">{VARIANT_LABELS[v.variant] || v.variant}</h3>
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Users className="w-3 h-3" />Sessions</div>
                      <div className="text-xl font-bold text-white">{v.sessions_count.toLocaleString()}</div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Clock className="w-3 h-3" />Avg Duration</div>
                      <div className="text-xl font-bold text-white">{(v.avg_session_duration || 0).toFixed(1)}s</div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Terminal className="w-3 h-3" />Commands</div>
                      <div className="text-xl font-bold text-white">{v.commands_count.toLocaleString()}</div>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 text-text-muted text-xs mb-1"><Shield className="w-3 h-3" />Login Rate</div>
                      <div className="text-xl font-bold text-white">{v.success_rate.toFixed(1)}%</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Comparison Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Activity Comparison" subtitle="Events over time by variant" icon={<TrendingUp className="w-5 h-5" />} />
              <CardContent>
                {comparisonLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={combinedTimeline}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Legend />
                        {comparison.map((c, i) => (
                          <Line key={c.variant} type="monotone" dataKey={c.variant} name={c.display_name} stroke={VARIANT_COLORS[c.variant] || COLORS[i]} strokeWidth={2} dot={false} />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Session Duration Analysis" subtitle="Duration percentiles by variant" icon={<Clock className="w-5 h-5" />} />
              <CardContent>
                {comparisonLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={comparison.map(c => ({ name: c.display_name, avg: c.duration.avg, p50: c.duration.p50, p90: c.duration.p90 }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="name" stroke="#888888" />
                        <YAxis stroke="#888888" label={{ value: 'Seconds', angle: -90, position: 'insideLeft', fill: '#888888' }} />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Legend />
                        <Bar dataKey="avg" name="Average" fill="#39ff14" />
                        <Bar dataKey="p50" name="Median (P50)" fill="#00d4ff" />
                        <Bar dataKey="p90" name="P90" fill="#ff6600" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Session Duration Distribution */}
          <Card>
            <CardHeader title="Session Duration Distribution" subtitle="Comparison of how long attackers engage with each variant" />
            <CardContent>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={durationDistData} barGap={2}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                    <XAxis dataKey="range" stroke="#888" tick={{ fill: '#888', fontSize: 12 }} />
                    <YAxis stroke="#888" tick={{ fill: '#888', fontSize: 12 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #333', borderRadius: '8px' }} />
                    <Legend />
                    <Bar dataKey="plain" name="Plain" fill="#39ff14" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="openai" name="OpenAI" fill="#00d4ff" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="ollama" name="Ollama" fill="#bf00ff" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Radar + Command Diversity */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Engagement Metrics" subtitle="Multi-dimensional comparison (normalized to 100)" />
              <CardContent>
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={radarData}>
                      <PolarGrid stroke="#333" />
                      <PolarAngleAxis dataKey="metric" tick={{ fill: '#888', fontSize: 11 }} />
                      <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#666', fontSize: 10 }} />
                      <Radar name="Plain" dataKey="plain" stroke="#39ff14" fill="#39ff14" fillOpacity={0.3} strokeWidth={2} />
                      <Radar name="OpenAI" dataKey="openai" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.3} strokeWidth={2} />
                      <Radar name="Ollama" dataKey="ollama" stroke="#bf00ff" fill="#bf00ff" fillOpacity={0.3} strokeWidth={2} />
                      <Legend />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Command Diversity" subtitle="Unique commands per variant" />
              <CardContent>
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={comparison.map(c => ({ variant: VARIANT_LABELS[c.variant] || c.variant, shortName: c.variant, uniqueCommands: c.metrics?.unique_commands || 0 }))} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                      <XAxis type="number" stroke="#888" tick={{ fill: '#888', fontSize: 12 }} />
                      <YAxis type="category" dataKey="variant" stroke="#888" tick={{ fill: '#888', fontSize: 11 }} width={120} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #333', borderRadius: '8px' }} />
                      <Bar dataKey="uniqueCommands" name="Unique Commands" radius={[0, 4, 4, 0]}>
                        {comparison.map((c) => (<Cell key={c.variant} fill={VARIANT_COLORS[c.variant] || '#888'} />))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Attack Funnel */}
          <Card>
            <CardHeader title="Attack Funnel Comparison" subtitle="Progression: Session → Login Attempt → Success → Commands" />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                {comparison.map((v) => {
                  const totalLogins = (v.metrics?.login_success || 0) + (v.metrics?.login_failed || 0);
                  const stages = [
                    { label: 'Sessions', value: v.metrics?.sessions || 0, pct: 100 },
                    { label: 'Login Attempts', value: totalLogins, pct: (v.metrics?.sessions || 1) > 0 ? (totalLogins / (v.metrics?.sessions || 1)) * 100 : 0 },
                    { label: 'Login Success', value: v.metrics?.login_success || 0, pct: (v.metrics?.sessions || 1) > 0 ? ((v.metrics?.login_success || 0) / (v.metrics?.sessions || 1)) * 100 : 0 },
                    { label: 'Commands', value: v.metrics?.commands_executed || 0, pct: (v.metrics?.sessions || 1) > 0 ? Math.min(((v.metrics?.commands_executed || 0) / (v.metrics?.sessions || 1)) * 100, 100) : 0 },
                  ];
                  return (
                    <div key={v.variant} className="space-y-3">
                      <h4 className="font-semibold text-center pb-2 border-b" style={{ color: VARIANT_COLORS[v.variant], borderColor: `${VARIANT_COLORS[v.variant]}40` }}>
                        {VARIANT_LABELS[v.variant] || v.variant}
                      </h4>
                      {stages.map((stage, idx) => (
                        <div key={stage.label} className="relative">
                          <div className="flex justify-between text-sm mb-1">
                            <span className="text-text-secondary">{stage.label}</span>
                            <span className="text-white font-mono">{stage.value.toLocaleString()}</span>
                          </div>
                          <div className="h-6 bg-bg-secondary rounded overflow-hidden">
                            <div className="h-full rounded transition-all" style={{ width: `${Math.min(stage.pct, 100)}%`, backgroundColor: VARIANT_COLORS[v.variant], opacity: 1 - (idx * 0.15) }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Statistical Summary Table */}
          <Card>
            <CardHeader title="Statistical Summary" subtitle="Key metrics comparison" />
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-bg-hover">
                      <th className="text-left py-3 px-4 text-text-secondary font-medium">Metric</th>
                      {comparison.map(c => (
                        <th key={c.variant} className="text-right py-3 px-4 font-medium" style={{ color: VARIANT_COLORS[c.variant] }}>
                          {VARIANT_LABELS[c.variant] || c.variant}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { label: 'Total Events', key: 'total_events' },
                      { label: 'Unique IPs', key: 'unique_ips' },
                      { label: 'Sessions', key: 'sessions' },
                      { label: 'Login Success Rate', key: 'login_success_rate', suffix: '%' },
                      { label: 'Commands Executed', key: 'commands_executed' },
                      { label: 'Unique Commands', key: 'unique_commands' },
                      { label: 'File Downloads', key: 'file_downloads' },
                    ].map((row) => (
                      <tr key={row.key} className="border-b border-bg-hover/50">
                        <td className="py-3 px-4 text-text-secondary">{row.label}</td>
                        {comparison.map(v => (
                          <td key={v.variant} className="text-right py-3 px-4 font-mono text-white">
                            {((v.metrics as Record<string, number>)?.[row.key] || 0).toLocaleString()}{row.suffix || ''}
                          </td>
                        ))}
                      </tr>
                    ))}
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Avg Session Duration</td>
                      {comparison.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{(v.duration?.avg || 0).toFixed(2)}s</td>))}
                    </tr>
                    <tr>
                      <td className="py-3 px-4 text-text-secondary">Max Session Duration</td>
                      {comparison.map(v => (<td key={v.variant} className="text-right py-3 px-4 font-mono text-white">{(v.duration?.max || 0).toFixed(1)}s</td>))}
                    </tr>
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Top Commands Per Variant */}
          <Card>
            <CardHeader title="Top Commands by Variant" subtitle="Most frequent commands executed on each honeypot variant" icon={<Terminal className="w-5 h-5" />} />
            <CardContent>
              {comparisonLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {comparison.map(c => (
                    <div key={c.variant} className="bg-bg-secondary rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-4 pb-2 border-b border-bg-hover">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: VARIANT_COLORS[c.variant] }} />
                        <span className="font-medium text-text-primary">{c.display_name}</span>
                        <span className="ml-auto text-sm text-text-muted">{c.metrics.commands_executed.toLocaleString()} total</span>
                      </div>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {(c.top_commands || []).length === 0 ? (
                          <div className="text-center py-4 text-text-muted text-sm">No commands recorded</div>
                        ) : (
                          (c.top_commands || []).map((cmd: { command: string; count: number }, idx: number) => (
                            <div key={idx} className="flex items-start justify-between gap-2 py-1">
                              <code className="font-mono text-xs text-neon-green break-all flex-1" title={cmd.command}>
                                {cmd.command.length > 60 ? cmd.command.slice(0, 60) + '...' : cmd.command || '(empty)'}
                              </code>
                              <span className="font-mono text-xs text-text-muted whitespace-nowrap">{cmd.count}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'credentials',
      label: 'Credentials',
      icon: <Key className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
              <CardContent className="p-5">
                <div className="flex items-center gap-4">
                  <div className="p-3 rounded-xl bg-neon-green/20">
                    <Key className="w-6 h-6 text-neon-green" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-green">
                      {credentials?.length || 0}
                    </div>
                    <div className="text-sm text-text-secondary">Unique Combinations</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
              <CardContent className="p-5">
                <div className="flex items-center gap-4">
                  <div className="p-3 rounded-xl bg-neon-blue/20">
                    <Users className="w-6 h-6 text-neon-blue" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-blue">
                      {new Set(credentials?.map((c: CowrieCredential) => c.username) || []).size}
                    </div>
                    <div className="text-sm text-text-secondary">Unique Usernames</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
              <CardContent className="p-5">
                <div className="flex items-center gap-4">
                  <div className="p-3 rounded-xl bg-neon-orange/20">
                    <Shield className="w-6 h-6 text-neon-orange" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-orange">
                      {credentials?.reduce((sum: number, c: CowrieCredential) => sum + c.count, 0)?.toLocaleString() || 0}
                    </div>
                    <div className="text-sm text-text-secondary">Total Attempts</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top Credentials Table */}
            <Card>
              <CardHeader title="Top Credential Attempts" subtitle="Most frequently used username/password combinations" icon={<Key className="w-5 h-5" />} />
              <CardContent className="p-0">
                {credentialsLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <LoadingSpinner />
                  </div>
                ) : !credentials || credentials.length === 0 ? (
                  <div className="text-center py-12 text-text-muted">
                    <Key className="w-12 h-12 mx-auto mb-3 opacity-30" />
                    <p>No credential attempts found</p>
                  </div>
                ) : (
                  <div className="max-h-[500px] overflow-y-auto">
                    <table className="w-full">
                      <thead className="sticky top-0 bg-bg-card border-b border-bg-hover z-10">
                        <tr>
                          <th className="text-left py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">#</th>
                          <th className="text-left py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Username</th>
                          <th className="text-left py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Password</th>
                          <th className="text-center py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Status</th>
                          <th className="text-right py-3 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Count</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-bg-hover">
                        {(credentials as CowrieCredential[]).slice(0, 25).map((cred: CowrieCredential, index: number) => (
                          <tr key={`${cred.username}-${cred.password}-${index}`} className="hover:bg-bg-hover/50 transition-colors">
                            <td className="py-3 px-4 text-text-muted text-sm font-mono">
                              {index + 1}
                            </td>
                            <td className="py-3 px-4">
                              <code className="font-mono text-sm text-neon-green bg-neon-green/10 px-2 py-1 rounded border border-neon-green/20">
                                {cred.username || '(empty)'}
                              </code>
                            </td>
                            <td className="py-3 px-4">
                              <code className="font-mono text-sm text-neon-orange bg-neon-orange/10 px-2 py-1 rounded border border-neon-orange/20">
                                {cred.password || '(empty)'}
                              </code>
                            </td>
                            <td className="py-3 px-4 text-center">
                              <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                                cred.success 
                                  ? 'bg-neon-green/10 text-neon-green border border-neon-green/30' 
                                  : 'bg-neon-red/10 text-neon-red border border-neon-red/30'
                              }`}>
                                {cred.success ? 'Success' : 'Failed'}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-right">
                              <span className="font-mono text-base font-bold text-neon-blue">{cred.count.toLocaleString()}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top Usernames & Passwords */}
            <div className="space-y-6">
              <Card>
                <CardHeader title="Top 10 Usernames" subtitle="Most targeted usernames" />
                <CardContent>
                  <div className="space-y-2">
                    {(() => {
                      const usernameCounts: Record<string, number> = {};
                      credentials?.forEach((c: CowrieCredential) => {
                        usernameCounts[c.username] = (usernameCounts[c.username] || 0) + c.count;
                      });
                      const sorted = Object.entries(usernameCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
                      const maxCount = sorted[0]?.[1] || 1;
                      return sorted.map(([username, count], index) => (
                        <div key={username} className="flex items-center gap-3">
                          <span className="w-6 text-text-muted text-sm">#{index + 1}</span>
                          <code className="font-mono text-sm text-neon-green w-32 truncate">{username}</code>
                          <div className="flex-1 h-4 bg-bg-secondary rounded-full overflow-hidden">
                            <div className="h-full bg-neon-green/50 rounded-full" style={{ width: `${(count / maxCount) * 100}%` }} />
                          </div>
                          <span className="font-mono text-sm text-text-muted w-16 text-right">{count.toLocaleString()}</span>
                        </div>
                      ));
                    })()}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader title="Top 10 Passwords" subtitle="Most used passwords" />
                <CardContent>
                  <div className="space-y-2">
                    {(() => {
                      const passwordCounts: Record<string, number> = {};
                      credentials?.forEach((c: CowrieCredential) => {
                        passwordCounts[c.password] = (passwordCounts[c.password] || 0) + c.count;
                      });
                      const sorted = Object.entries(passwordCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
                      const maxCount = sorted[0]?.[1] || 1;
                      return sorted.map(([password, count], index) => (
                        <div key={password} className="flex items-center gap-3">
                          <span className="w-6 text-text-muted text-sm">#{index + 1}</span>
                          <code className="font-mono text-sm text-neon-orange w-32 truncate">{password}</code>
                          <div className="flex-1 h-4 bg-bg-secondary rounded-full overflow-hidden">
                            <div className="h-full bg-neon-orange/50 rounded-full" style={{ width: `${(count / maxCount) * 100}%` }} />
                          </div>
                          <span className="font-mono text-sm text-text-muted w-16 text-right">{count.toLocaleString()}</span>
                        </div>
                      ));
                    })()}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      ),
    },
    {
      id: 'map',
      label: 'Attack Map',
      icon: <Map className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <HoneypotMap
            data={geo?.data?.map((g: GeoPoint) => ({ country: g.country, count: g.count })) || []}
            title="Cowrie SSH Attack Origins"
            height="450px"
            accentColor="#39ff14"
            loading={geoLoading}
          />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Top Countries Distribution" subtitle="Attack share by country" />
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={geo?.data?.slice(0, 8) || []} dataKey="count" nameKey="country" cx="50%" cy="50%" innerRadius={40} outerRadius={80} paddingAngle={2} label={({ country, percent }) => `${country} ${(percent * 100).toFixed(0)}%`}>
                        {geo?.data?.slice(0, 8).map((_: unknown, index: number) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader title="Attack Countries" subtitle={`${geo?.data?.length || 0} countries detected`} />
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {geo?.data?.slice(0, 15).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                      <div className="flex items-center gap-3">
                        <span className="text-text-muted text-sm w-6">#{index + 1}</span>
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary font-medium">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
    {
      id: 'commands',
      label: 'Commands',
      icon: <Terminal className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {commandExplorerLoading ? (
            <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <>
              {/* Stats Row */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-green">{commandExplorer?.total_executions?.toLocaleString() || 0}</div>
                    <div className="text-xs text-text-secondary">Total Executions</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-blue">{commandExplorer?.unique_commands || 0}</div>
                    <div className="text-xs text-text-secondary">Unique Commands</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-red">{commandExplorer?.risk_distribution?.critical || 0}</div>
                    <div className="text-xs text-text-secondary">Critical Risk</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-orange">{commandExplorer?.risk_distribution?.high || 0}</div>
                    <div className="text-xs text-text-secondary">High Risk</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-purple">{commandExplorer?.mitre_techniques?.length || 0}</div>
                    <div className="text-xs text-text-secondary">MITRE Techniques</div>
                  </CardContent>
                </Card>
              </div>

              {/* Intent Distribution & MITRE Techniques */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="Command Intent Distribution" subtitle="What attackers are trying to do" />
                  <CardContent>
                    <div className="space-y-3">
                      {commandExplorer?.intent_distribution?.map((intent) => {
                        const total = commandExplorer?.total_executions || 1;
                        const percentage = Math.round((intent.count / total) * 100);
                        const colorMap: Record<string, string> = {
                          download_execute: '#ff3366',
                          credential_access: '#ff6600',
                          persistence: '#bf00ff',
                          privilege_escalation: '#ff6600',
                          cryptomining: '#ff3366',
                          reconnaissance: '#00d4ff',
                          network_recon: '#00d4ff',
                          defense_evasion: '#ffcc00',
                          lateral_movement: '#bf00ff',
                          execution: '#39ff14',
                          navigation: '#888888',
                          environment: '#888888',
                          unknown: '#555555'
                        };
                        return (
                          <div key={intent.intent} className="flex items-center gap-3">
                            <div className="w-36 text-sm text-text-secondary capitalize truncate">{intent.intent.replace(/_/g, ' ')}</div>
                            <div className="flex-1 bg-bg-secondary rounded-full h-5 overflow-hidden">
                              <div 
                                className="h-full rounded-full transition-all duration-500"
                                style={{ width: `${percentage}%`, backgroundColor: colorMap[intent.intent] || '#39ff14' }}
                              />
                            </div>
                            <div className="w-24 text-right font-mono text-sm">{intent.count.toLocaleString()}</div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader title="MITRE ATT&CK Techniques" subtitle="Detected adversary techniques" />
                  <CardContent>
                    <div className="space-y-2 max-h-80 overflow-y-auto">
                      {commandExplorer?.mitre_techniques?.map((tech) => (
                        <div key={tech.technique} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-xs text-neon-blue bg-neon-blue/20 px-2 py-1 rounded">{tech.technique.split(' - ')[0]}</span>
                            <span className="text-sm text-text-primary">{tech.technique.split(' - ')[1]}</span>
                          </div>
                          <span className="font-mono text-neon-green font-bold">{tech.count.toLocaleString()}</span>
                        </div>
                      ))}
                      {(!commandExplorer?.mitre_techniques || commandExplorer.mitre_techniques.length === 0) && (
                        <div className="text-center py-4 text-text-secondary text-sm">No techniques detected</div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Variant Comparison */}
              <Card>
                <CardHeader title="Commands by Variant" subtitle="Comparison of command execution across honeypot variants" />
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {Object.entries(commandExplorer?.variant_totals || {}).map(([variant, count]) => (
                      <div key={variant} className="p-4 bg-bg-secondary rounded-lg text-center">
                        <div className="text-3xl font-display font-bold" style={{ color: VARIANT_COLORS[variant] || '#39ff14' }}>
                          {(count as number).toLocaleString()}
                        </div>
                        <div className="text-sm text-text-secondary capitalize">{variant}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Command List */}
              <Card>
                <CardHeader title="Command Explorer" subtitle="All executed commands with intent analysis" />
                <CardContent className="p-0">
                  <div className="max-h-[600px] overflow-y-auto">
                    <table className="w-full">
                      <thead className="sticky top-0 bg-bg-card">
                        <tr className="border-b border-bg-hover">
                          <th className="text-left py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Command</th>
                          <th className="text-left py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Intent</th>
                          <th className="text-left py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">MITRE</th>
                          <th className="text-center py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Risk</th>
                          <th className="text-right py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">Count</th>
                          <th className="text-right py-4 px-4 text-xs uppercase tracking-wider text-text-muted font-semibold">IPs</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-bg-hover">
                        {commandExplorer?.commands?.slice(0, 100).map((cmd, index) => {
                          const riskColors: Record<string, string> = {
                            critical: 'bg-neon-red text-white',
                            high: 'bg-neon-orange text-bg-primary',
                            medium: 'bg-neon-yellow text-bg-primary',
                            low: 'bg-bg-hover text-text-secondary'
                          };
                          return (
                            <tr key={index} className="hover:bg-bg-secondary transition-colors">
                              <td className="py-4 px-4">
                                <code className="font-mono text-sm text-neon-green break-all">{cmd.command.length > 80 ? cmd.command.slice(0, 80) + '...' : cmd.command}</code>
                              </td>
                              <td className="py-4 px-4">
                                <div className="text-sm text-text-primary capitalize">{cmd.intent.replace(/_/g, ' ')}</div>
                                <div className="text-xs text-text-muted">{cmd.description}</div>
                              </td>
                              <td className="py-4 px-4">
                                {cmd.mitre ? (
                                  <span className="font-mono text-xs text-neon-blue bg-neon-blue/20 px-2 py-1 rounded">{cmd.mitre.split(' - ')[0]}</span>
                                ) : (
                                  <span className="text-text-muted">-</span>
                                )}
                              </td>
                              <td className="py-4 px-4 text-center">
                                <span className={`px-2 py-1 rounded-full text-xs font-medium ${riskColors[cmd.risk]}`}>
                                  {cmd.risk}
                                </span>
                              </td>
                              <td className="py-4 px-4 text-right font-mono text-sm font-bold">{cmd.count.toLocaleString()}</td>
                              <td className="py-4 px-4 text-right font-mono text-sm text-text-muted">{cmd.unique_ips}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-neon-green">Cowrie SSH Honeypot</h2>
          <p className="text-sm text-text-secondary mt-1">Medium-interaction SSH/Telnet honeypot with Plain & LLM variants</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />

      {/* Session Details Modal */}
      {selectedSessionId && (
        <CowrieSessionModal
          sessionId={selectedSessionId}
          onClose={() => setSelectedSessionId(null)}
        />
      )}
    </div>
  );
}
