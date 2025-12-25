import { useCallback, useState } from 'react';
import {
  BarChart2,
  Clock,
  Map,
  Terminal,
  Key,
  Fingerprint,
  GitCompare,
  TrendingUp,
  CheckCircle,
  XCircle,
  Eye,
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
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { CowrieSession, CowrieCredential, CowrieHassh, GeoPoint } from '../types';

const COLORS = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'];
const VARIANT_COLORS: Record<string, string> = {
  'plain': '#39ff14',
  'llm': '#00d4ff',
  'openai': '#ff6600',
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
}

export default function Cowrie() {
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [selectedVariant, setSelectedVariant] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: sessions, loading: sessionsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieSessions(timeRange, 50), [timeRange]),
    [timeRange]
  );

  const { data: credentials, loading: credentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCredentials(timeRange, 50), [timeRange]),
    [timeRange]
  );

  const { data: commands, loading: commandsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCommands(timeRange, 30), [timeRange]),
    [timeRange]
  );

  const { data: hassh, loading: hasshLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieHashh(timeRange, 20), [timeRange]),
    [timeRange]
  );

  const { data: variantsData, loading: variantsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieVariants(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: comparisonData, loading: comparisonLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieVariantComparison(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: loginAnalysis, loading: loginAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieLoginAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: sessionDurations, loading: sessionDurationsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieSessionDurations(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: attackFunnel, loading: attackFunnelLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieAttackFunnel(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentialReuse, loading: credentialReuseLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCredentialReuse(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: clientFingerprints, loading: clientFingerprintsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieClientFingerprints(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: weakAlgorithms, loading: weakAlgorithmsLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieWeakAlgorithms(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: commandCategories, loading: commandCategoriesLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCommandCategories(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: commandExplorer, loading: commandExplorerLoading } = useApiWithRefresh(
    useCallback(() => api.getCowrieCommandExplorer(timeRange), [timeRange]),
    [timeRange]
  );

  const variants = (variantsData?.variants || []) as unknown as VariantData[];
  const comparison = (comparisonData?.comparison || []) as unknown as ComparisonData[];

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const formatDuration = (seconds?: number | null) => {
    if (seconds === null || seconds === undefined) return 'N/A';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${Math.round(seconds / 3600)}h`;
  };

  const sessionColumns = [
    {
      key: 'session_id',
      header: 'Session',
      render: (item: CowrieSession) => (
        <button 
          onClick={() => setSelectedSessionId(item.session_id)}
          className="font-mono text-xs text-neon-blue hover:underline cursor-pointer"
        >
          {item.session_id.slice(0, 12)}...
        </button>
      ),
    },
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: CowrieSession) => <IPLink ip={item.src_ip} />,
    },
    {
      key: 'sensor',
      header: 'Variant',
      render: (item: CowrieSession) => {
        const sensor = (item as unknown as { sensor?: string }).sensor || '';
        const color = VARIANT_COLORS[sensor] || '#888888';
        return (
          <span className="font-mono text-xs" style={{ color }}>
            {sensor.replace('cowrie_', '')}
          </span>
        );
      },
    },
    {
      key: 'duration',
      header: 'Duration',
      render: (item: CowrieSession) => (
        <span className="text-text-secondary">{formatDuration(item.duration)}</span>
      ),
    },
    {
      key: 'commands_count',
      header: 'Commands',
      render: (item: CowrieSession) => (
        <button
          onClick={() => setSelectedSessionId(item.session_id)}
          className="font-mono text-neon-green hover:underline cursor-pointer flex items-center gap-1"
        >
          {item.commands_count}
          {item.commands_count > 0 && <Eye className="w-3 h-3" />}
        </button>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (item: CowrieSession) => (
        <span className="text-text-secondary">{item.country || 'Unknown'}</span>
      ),
    },
  ];

  const credentialColumns = [
    {
      key: 'username',
      header: 'Username',
      render: (item: CowrieCredential) => (
        <span className="font-mono text-neon-blue">{item.username}</span>
      ),
    },
    {
      key: 'password',
      header: 'Password',
      render: (item: CowrieCredential) => (
        <span className="font-mono text-neon-orange">{item.password}</span>
      ),
    },
    {
      key: 'success',
      header: 'Status',
      render: (item: CowrieCredential) => (
        item.success ? (
          <span className="flex items-center text-neon-green"><CheckCircle className="w-4 h-4 mr-1" /> Success</span>
        ) : (
          <span className="flex items-center text-neon-red"><XCircle className="w-4 h-4 mr-1" /> Failed</span>
        )
      ),
    },
    {
      key: 'count',
      header: 'Attempts',
      render: (item: CowrieCredential) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
      ),
    },
  ];

  // Combined timeline data
  const combinedTimeline = comparison.length > 0 ? (() => {
    const timeMap: Record<string, Record<string, number>> = {};
    comparison.forEach(c => {
      c.timeline.forEach(t => {
        if (!timeMap[t.timestamp]) timeMap[t.timestamp] = {};
        timeMap[t.timestamp][c.variant] = t.count;
      });
    });
    return Object.entries(timeMap)
      .map(([timestamp, data]) => ({ timestamp, ...data }))
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  })() : [];

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
            <CardHeader title="Event Timeline" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorCowrie" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#39ff14" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#39ff14" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#39ff14" fill="url(#colorCowrie)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Recent Sessions" icon={<Terminal className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable columns={sessionColumns} data={sessions || []} loading={sessionsLoading} emptyMessage="No sessions found" />
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
          {/* Variant Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {variantsLoading ? (
              <div className="col-span-3 flex items-center justify-center py-12"><LoadingSpinner /></div>
            ) : variants.map((v, i) => (
              <div
                key={v.variant}
                className={`p-5 bg-bg-secondary rounded-xl border-2 cursor-pointer transition-all ${
                  selectedVariant === v.variant ? 'border-neon-green shadow-lg shadow-neon-green/10' : 'border-bg-hover hover:border-bg-card'
                }`}
                onClick={() => setSelectedVariant(selectedVariant === v.variant ? null : v.variant)}
              >
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-lg font-display font-bold" style={{ color: VARIANT_COLORS[v.variant] || COLORS[i] }}>
                    {v.display_name}
                  </h4>
                  <span className="text-2xl font-display font-bold text-text-primary">
                    {v.total_events.toLocaleString()}
                  </span>
                </div>
                
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="bg-bg-card rounded-lg p-2">
                    <div className="text-text-secondary text-xs">Unique IPs</div>
                    <div className="font-mono text-text-primary">{v.unique_ips}</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-2">
                    <div className="text-text-secondary text-xs">Sessions</div>
                    <div className="font-mono text-text-primary">{v.sessions_count}</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-2">
                    <div className="text-text-secondary text-xs">Login Success</div>
                    <div className="font-mono text-neon-green">{v.success_rate}%</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-2">
                    <div className="text-text-secondary text-xs">Avg Duration</div>
                    <div className="font-mono text-neon-blue">{formatDuration(v.avg_session_duration)}</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-2">
                    <div className="text-text-secondary text-xs">Commands</div>
                    <div className="font-mono text-neon-orange">{v.commands_count}</div>
                  </div>
                  <div className="bg-bg-card rounded-lg p-2">
                    <div className="text-text-secondary text-xs">Downloads</div>
                    <div className="font-mono text-neon-purple">{v.file_downloads}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Comparison Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Timeline Comparison */}
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
                          <Line
                            key={c.variant}
                            type="monotone"
                            dataKey={c.variant}
                            name={c.display_name}
                            stroke={VARIANT_COLORS[c.variant] || COLORS[i]}
                            strokeWidth={2}
                            dot={false}
                          />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Duration Comparison */}
            <Card>
              <CardHeader title="Session Duration Analysis" subtitle="Duration percentiles by variant" icon={<Clock className="w-5 h-5" />} />
              <CardContent>
                {comparisonLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={comparison.map(c => ({
                        name: c.display_name,
                        avg: c.duration.avg,
                        p50: c.duration.p50,
                        p90: c.duration.p90,
                        p99: c.duration.p99,
                      }))}>
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

          {/* Metrics Comparison Table */}
          <Card>
            <CardHeader title="Detailed Metrics Comparison" icon={<BarChart2 className="w-5 h-5" />} />
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-bg-hover">
                      <th className="text-left py-3 px-4 text-text-secondary font-medium">Metric</th>
                      {comparison.map(c => (
                        <th key={c.variant} className="text-right py-3 px-4 font-medium" style={{ color: VARIANT_COLORS[c.variant] }}>
                          {c.display_name}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Total Events</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-text-primary">{c.metrics.total_events.toLocaleString()}</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Unique IPs</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-text-primary">{c.metrics.unique_ips}</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Sessions</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-text-primary">{c.metrics.sessions}</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Login Success Rate</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-neon-green">{c.metrics.login_success_rate}%</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Commands Executed</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-text-primary">{c.metrics.commands_executed}</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Unique Commands</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-text-primary">{c.metrics.unique_commands}</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">File Downloads</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-neon-purple">{c.metrics.file_downloads}</td>
                      ))}
                    </tr>
                    <tr className="border-b border-bg-hover/50">
                      <td className="py-3 px-4 text-text-secondary">Avg Session Duration</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-neon-blue">{formatDuration(c.duration.avg)}</td>
                      ))}
                    </tr>
                    <tr>
                      <td className="py-3 px-4 text-text-secondary">Max Session Duration</td>
                      {comparison.map(c => (
                        <td key={c.variant} className="text-right py-3 px-4 font-mono text-neon-orange">{formatDuration(c.duration.max)}</td>
                      ))}
                    </tr>
                  </tbody>
                </table>
              </div>
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
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Top Credential Attempts" />
              <CardContent className="p-0">
                <DataTable columns={credentialColumns} data={credentials || []} loading={credentialsLoading} emptyMessage="No credentials found" />
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Command Analysis" subtitle="What attackers are trying to do" icon={<Terminal className="w-5 h-5" />} />
              <CardContent>
                {commandsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {commands?.slice(0, 15).map((cmd, index) => {
                      // Analyze command intent
                      const cmdLower = (cmd.command || '').toLowerCase();
                      let intent = '';
                      let intentColor = 'text-text-muted';
                      let category = '';
                      
                      if (cmdLower.includes('cat /proc') || cmdLower.includes('uname') || cmdLower.includes('whoami') || cmdLower.includes('id') || cmdLower.includes('hostname')) {
                        intent = 'System reconnaissance - gathering system information';
                        intentColor = 'text-neon-blue';
                        category = '🔍 Recon';
                      } else if (cmdLower.includes('wget') || cmdLower.includes('curl') || cmdLower.includes('tftp')) {
                        intent = 'Payload download - attempting to fetch malware';
                        intentColor = 'text-neon-red';
                        category = '📥 Download';
                      } else if (cmdLower.includes('chmod') || cmdLower.includes('chattr')) {
                        intent = 'Permission modification - preparing for execution';
                        intentColor = 'text-neon-orange';
                        category = '🔓 Persist';
                      } else if (cmdLower.includes('rm ') || cmdLower.includes('rm -rf')) {
                        intent = 'Evidence cleanup - removing traces';
                        intentColor = 'text-neon-purple';
                        category = '🧹 Cleanup';
                      } else if (cmdLower.includes('export') || cmdLower.includes('path=')) {
                        intent = 'Environment setup - configuring shell';
                        intentColor = 'text-neon-yellow';
                        category = '⚙️ Setup';
                      } else if (cmdLower.includes('cd ') || cmdLower.includes('ls') || cmdLower.includes('pwd')) {
                        intent = 'Directory navigation - exploring filesystem';
                        intentColor = 'text-text-secondary';
                        category = '📂 Navigate';
                      } else if (cmdLower.includes('ps ') || cmdLower.includes('top') || cmdLower.includes('free')) {
                        intent = 'Process/resource check - analyzing system state';
                        intentColor = 'text-neon-blue';
                        category = '🔍 Recon';
                      } else if (cmdLower.includes('crontab') || cmdLower.includes('systemctl') || cmdLower.includes('service')) {
                        intent = 'Persistence setup - establishing backdoor';
                        intentColor = 'text-neon-red';
                        category = '🚪 Persist';
                      } else if (cmdLower.includes('netstat') || cmdLower.includes('ss ') || cmdLower.includes('ifconfig') || cmdLower.includes('ip addr')) {
                        intent = 'Network reconnaissance - mapping network';
                        intentColor = 'text-neon-blue';
                        category = '🌐 Network';
                      } else if (cmdLower.includes('lscpu') || cmdLower.includes('df ') || cmdLower.includes('free')) {
                        intent = 'Resource check - evaluating for mining';
                        intentColor = 'text-neon-orange';
                        category = '⛏️ Mining';
                      } else if (cmdLower.includes('history') || cmdLower.includes('cat /etc/passwd')) {
                        intent = 'Credential/history theft - stealing data';
                        intentColor = 'text-neon-red';
                        category = '🔑 Creds';
                      } else {
                        intent = 'General command execution';
                        intentColor = 'text-text-muted';
                        category = '💻 Exec';
                      }
                      
                      return (
                        <div key={index} className="p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                          <div className="flex items-start justify-between gap-2 mb-1">
                            <code className="font-mono text-sm text-neon-green break-all flex-1">{cmd.command}</code>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              <span className="px-2 py-0.5 text-xs bg-bg-card rounded-full">{category}</span>
                              <span className="font-mono text-text-muted text-sm">{cmd.count}×</span>
                            </div>
                          </div>
                          <div className={`text-xs ${intentColor}`}>{intent}</div>
                        </div>
                      );
                    })}
                    {(!commands || commands.length === 0) && (
                      <div className="text-center py-8 text-text-secondary">No commands recorded</div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
    {
      id: 'map',
      label: 'Geographic',
      icon: <Map className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Attack Origins" />
          <CardContent>
            {geoLoading ? (
              <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={geo?.data?.slice(0, 8) || []} dataKey="count" nameKey="country" cx="50%" cy="50%" outerRadius={120} label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`} labelLine={false}>
                        {geo?.data?.slice(0, 8).map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-2">
                  {geo?.data?.slice(0, 15).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'hassh',
      label: 'HASSH',
      icon: <Fingerprint className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="SSH Fingerprints (HASSH)" subtitle="Client identification via SSH algorithm negotiation" />
          <CardContent>
            {hasshLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="space-y-3">
                {hassh?.map((item: CowrieHassh) => (
                  <div key={item.hassh} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                    <div>
                      <div className="font-mono text-sm text-neon-blue">{item.hassh}</div>
                      {item.client_version && <div className="text-xs text-text-secondary mt-1">{item.client_version}</div>}
                    </div>
                    <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                  </div>
                ))}
                {(!hassh || hassh.length === 0) && <div className="text-center py-8 text-text-secondary">No HASSH fingerprints found</div>}
              </div>
            )}
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'analytics',
      label: 'Analytics',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Attack Funnel */}
          <Card>
            <CardHeader title="Attack Progression Funnel" subtitle="How attackers progress through stages" />
            <CardContent>
              {attackFunnelLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="space-y-4">
                  <div className="grid grid-cols-4 gap-4">
                    {attackFunnel?.funnel?.map((stage, index) => (
                      <div key={stage.stage} className="text-center">
                        <div className="relative">
                          <div 
                            className="mx-auto rounded-lg p-4"
                            style={{ 
                              backgroundColor: `rgba(57, 255, 20, ${0.1 + (0.2 * (attackFunnel.funnel.length - index) / attackFunnel.funnel.length)})`,
                              width: `${100 - index * 15}%`
                            }}
                          >
                            <div className="text-2xl font-display font-bold text-neon-green">{stage.count.toLocaleString()}</div>
                            <div className="text-xs text-text-secondary mt-1">{stage.stage}</div>
                            <div className="text-xs text-neon-blue mt-1">{stage.percentage}%</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="text-center text-text-secondary text-sm">
                    Total Unique Sessions: <span className="text-neon-green font-bold">{attackFunnel?.total_sessions?.toLocaleString() || 0}</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Login Analysis by Sensor */}
            <Card>
              <CardHeader title="Login Success/Failure by Sensor" subtitle="Compare Plain vs LLM effectiveness" />
              <CardContent>
                {loginAnalysisLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={loginAnalysis?.sensors || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} />
                        <YAxis 
                          type="category" 
                          dataKey="sensor" 
                          stroke="#888888" 
                          tick={{ fill: '#888888', fontSize: 11 }} 
                          width={100}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                        />
                        <Legend />
                        <Bar dataKey="success" name="Success" fill="#39ff14" stackId="a" />
                        <Bar dataKey="failed" name="Failed" fill="#ff3366" stackId="a" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Session Duration Distribution */}
            <Card>
              <CardHeader title="Session Duration Distribution" subtitle="How long attackers stay connected" />
              <CardContent>
                {sessionDurationsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <>
                    <div className="grid grid-cols-3 gap-2 mb-4 text-center">
                      <div className="bg-bg-secondary rounded-lg p-2">
                        <div className="text-xs text-text-secondary">Avg</div>
                        <div className="text-lg font-bold text-neon-blue">{sessionDurations?.stats?.avg_duration || 0}s</div>
                      </div>
                      <div className="bg-bg-secondary rounded-lg p-2">
                        <div className="text-xs text-text-secondary">Median</div>
                        <div className="text-lg font-bold text-neon-green">{Math.round(sessionDurations?.stats?.percentiles?.['50.0'] || 0)}s</div>
                      </div>
                      <div className="bg-bg-secondary rounded-lg p-2">
                        <div className="text-xs text-text-secondary">Max</div>
                        <div className="text-lg font-bold text-neon-orange">{sessionDurations?.stats?.max_duration || 0}s</div>
                      </div>
                    </div>
                    <div className="h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={sessionDurations?.ranges || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis dataKey="range" stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                          <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#1a1a25',
                              border: '1px solid #252532',
                              borderRadius: '8px',
                              color: '#e0e0e0',
                            }}
                          />
                          <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Credential Reuse Analysis */}
          <Card>
            <CardHeader title="Credential Reuse Analysis" subtitle="Most commonly attempted passwords and usernames" />
            <CardContent>
              {credentialReuseLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">Top Passwords Attempted</h4>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {credentialReuse?.top_passwords?.map((item, index) => (
                        <div key={item.password} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <div className="flex items-center">
                            <span className="w-6 text-text-muted text-xs">{index + 1}.</span>
                            <span className="font-mono text-neon-red">{item.password}</span>
                          </div>
                          <span className="font-mono text-neon-green text-sm">{item.count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">Top Usernames Attempted</h4>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {credentialReuse?.top_usernames?.map((item, index) => (
                        <div key={item.username} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <div className="flex items-center">
                            <span className="w-6 text-text-muted text-xs">{index + 1}.</span>
                            <span className="font-mono text-neon-blue">{item.username}</span>
                          </div>
                          <span className="font-mono text-neon-green text-sm">{item.count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'fingerprinting',
      label: 'SSH Fingerprinting',
      icon: <Fingerprint className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* SSH Client Tools Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader 
                title="SSH Client Tools" 
                subtitle="Attack tools identified by version strings"
              />
              <CardContent>
                {clientFingerprintsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <>
                    <div className="mb-4 p-3 bg-bg-secondary rounded-lg flex items-center justify-between">
                      <span className="text-sm text-text-secondary">Unique Fingerprints</span>
                      <span className="font-mono text-lg text-neon-green font-bold">{clientFingerprints?.unique_fingerprints || 0}</span>
                    </div>
                    <div className="h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={clientFingerprints?.tools?.slice(0, 6) || []}
                            cx="50%"
                            cy="50%"
                            innerRadius={40}
                            outerRadius={70}
                            paddingAngle={2}
                            dataKey="count"
                            nameKey="tool"
                          >
                            {clientFingerprints?.tools?.slice(0, 6).map((_, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#1a1a25',
                              border: '1px solid #252532',
                              borderRadius: '8px',
                              color: '#e0e0e0',
                            }}
                            formatter={(value: number, name: string) => [value.toLocaleString(), name]}
                          />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader 
                title="SSH Version Strings" 
                subtitle="Raw version strings from clients"
              />
              <CardContent>
                {clientFingerprintsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto">
                    {clientFingerprints?.versions?.slice(0, 15).map((item, index) => (
                      <div key={item.version} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                        <div className="flex-1 min-w-0">
                          <span className="text-xs text-text-muted mr-2">{index + 1}.</span>
                          <span className="font-mono text-sm text-text-primary truncate">{item.version}</span>
                          <span className="ml-2 px-2 py-0.5 rounded text-xs bg-neon-blue/20 text-neon-blue">{item.tool}</span>
                        </div>
                        <span className="font-mono text-neon-green ml-2">{item.count}</span>
                      </div>
                    ))}
                    {(!clientFingerprints?.versions || clientFingerprints.versions.length === 0) && (
                      <div className="text-center py-8 text-text-secondary">No version data available</div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Weak Algorithms Detection */}
          <Card>
            <CardHeader 
              title="Weak Algorithm Detection" 
              subtitle="SSH clients using deprecated or weak cryptographic algorithms"
            />
            <CardContent>
              {weakAlgorithmsLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <>
                  {/* Summary Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-2xl font-display font-bold text-neon-green">{weakAlgorithms?.summary?.total_sessions || 0}</div>
                      <div className="text-xs text-text-secondary">Total Sessions</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-2xl font-display font-bold text-neon-red">{weakAlgorithms?.summary?.sessions_with_weak || 0}</div>
                      <div className="text-xs text-text-secondary">With Weak Algorithms</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-2xl font-display font-bold text-neon-orange">{weakAlgorithms?.summary?.weak_percentage || 0}%</div>
                      <div className="text-xs text-text-secondary">Percentage</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-2xl font-display font-bold text-neon-purple">{weakAlgorithms?.summary?.unique_attackers_with_weak || 0}</div>
                      <div className="text-xs text-text-secondary">Unique Attackers</div>
                    </div>
                  </div>

                  {/* Weak Algorithm Lists */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                      <h4 className="text-sm font-medium text-neon-red mb-3">Weak Ciphers</h4>
                      <div className="space-y-2">
                        {weakAlgorithms?.weak_ciphers?.map((item) => (
                          <div key={item.algorithm} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                            <span className="font-mono text-xs text-text-primary truncate">{item.algorithm}</span>
                            <span className="font-mono text-neon-red text-sm">{item.count}</span>
                          </div>
                        ))}
                        {(!weakAlgorithms?.weak_ciphers || weakAlgorithms.weak_ciphers.length === 0) && (
                          <div className="text-center py-4 text-text-secondary text-sm flex items-center justify-center gap-2">
                            <CheckCircle className="w-4 h-4 text-neon-green" /> None detected
                          </div>
                        )}
                      </div>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-neon-orange mb-3">Weak Key Exchange</h4>
                      <div className="space-y-2">
                        {weakAlgorithms?.weak_kex?.map((item) => (
                          <div key={item.algorithm} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                            <span className="font-mono text-xs text-text-primary truncate">{item.algorithm}</span>
                            <span className="font-mono text-neon-orange text-sm">{item.count}</span>
                          </div>
                        ))}
                        {(!weakAlgorithms?.weak_kex || weakAlgorithms.weak_kex.length === 0) && (
                          <div className="text-center py-4 text-text-secondary text-sm flex items-center justify-center gap-2">
                            <CheckCircle className="w-4 h-4 text-neon-green" /> None detected
                          </div>
                        )}
                      </div>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-neon-purple mb-3">Weak MAC</h4>
                      <div className="space-y-2">
                        {weakAlgorithms?.weak_mac?.map((item) => (
                          <div key={item.algorithm} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                            <span className="font-mono text-xs text-text-primary truncate">{item.algorithm}</span>
                            <span className="font-mono text-neon-purple text-sm">{item.count}</span>
                          </div>
                        ))}
                        {(!weakAlgorithms?.weak_mac || weakAlgorithms.weak_mac.length === 0) && (
                          <div className="text-center py-4 text-text-secondary text-sm flex items-center justify-center gap-2">
                            <CheckCircle className="w-4 h-4 text-neon-green" /> None detected
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Command Categorization with MITRE */}
          <Card>
            <CardHeader 
              title="Command Analysis with MITRE ATT&CK" 
              subtitle="Commands categorized by attack stage and mapped to MITRE techniques"
            />
            <CardContent>
              {commandCategoriesLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <>
                  {/* Category Summary */}
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                    {commandCategories?.categories?.map((cat) => (
                      <div key={cat.category} className="bg-bg-secondary rounded-lg p-3 text-center">
                        <div className="text-xl font-display font-bold text-neon-green">{cat.count.toLocaleString()}</div>
                        <div className="text-xs text-text-secondary">{cat.category}</div>
                      </div>
                    ))}
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* MITRE Techniques */}
                    <div>
                      <h4 className="text-sm font-medium text-text-secondary mb-3">Detected MITRE Techniques</h4>
                      <div className="space-y-2">
                        {commandCategories?.techniques?.map((tech) => (
                          <div key={tech.id} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                            <div>
                              <span className="font-mono text-xs text-neon-blue mr-2">{tech.id}</span>
                              <span className="text-sm text-text-primary">{tech.name}</span>
                              <span className="ml-2 px-1.5 py-0.5 text-xs bg-bg-hover rounded text-text-muted">{tech.tactic}</span>
                            </div>
                            <span className="font-mono text-neon-green">{tech.count}</span>
                          </div>
                        ))}
                        {(!commandCategories?.techniques || commandCategories.techniques.length === 0) && (
                          <div className="text-center py-4 text-text-secondary text-sm">No techniques detected</div>
                        )}
                      </div>
                    </div>

                    {/* Top Commands */}
                    <div>
                      <h4 className="text-sm font-medium text-text-secondary mb-3">Top Commands Executed</h4>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {commandCategories?.commands?.slice(0, 15).map((cmd, index) => (
                          <div key={index} className="p-2 bg-bg-secondary rounded-lg">
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-mono text-xs text-neon-green truncate max-w-[70%]">{cmd.command}</span>
                              <span className="font-mono text-text-muted text-xs">{cmd.count}x</span>
                            </div>
                            <div className="flex flex-wrap gap-1">
                              {cmd.techniques.map((t) => (
                                <span key={t} className="px-1 py-0.5 text-xs bg-neon-blue/20 text-neon-blue rounded">{t}</span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
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
                <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                  <div className="text-2xl font-display font-bold text-neon-green">{commandExplorer?.total_executions?.toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary">Total Executions</div>
                </div>
                <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                  <div className="text-2xl font-display font-bold text-neon-blue">{commandExplorer?.unique_commands || 0}</div>
                  <div className="text-xs text-text-secondary">Unique Commands</div>
                </div>
                <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                  <div className="text-2xl font-display font-bold text-neon-red">{commandExplorer?.risk_distribution?.critical || 0}</div>
                  <div className="text-xs text-text-secondary">Critical Risk</div>
                </div>
                <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                  <div className="text-2xl font-display font-bold text-neon-orange">{commandExplorer?.risk_distribution?.high || 0}</div>
                  <div className="text-xs text-text-secondary">High Risk</div>
                </div>
                <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
                  <div className="text-2xl font-display font-bold text-neon-purple">{commandExplorer?.mitre_techniques?.length || 0}</div>
                  <div className="text-xs text-text-secondary">MITRE Techniques</div>
                </div>
              </div>

              {/* Intent Distribution & MITRE Techniques */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="Command Intent Distribution" subtitle="What attackers are trying to do" />
                  <CardContent>
                    <div className="space-y-2">
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
                            <div className="w-32 text-sm text-text-secondary truncate">{intent.intent.replace('_', ' ')}</div>
                            <div className="flex-1 bg-bg-secondary rounded-full h-4 overflow-hidden">
                              <div 
                                className="h-full rounded-full transition-all duration-500"
                                style={{ width: `${percentage}%`, backgroundColor: colorMap[intent.intent] || '#39ff14' }}
                              />
                            </div>
                            <div className="w-20 text-right font-mono text-sm">{intent.count.toLocaleString()}</div>
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
                        <div key={tech.technique} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-neon-blue">{tech.technique.split(' - ')[0]}</span>
                            <span className="text-sm text-text-primary">{tech.technique.split(' - ')[1]}</span>
                          </div>
                          <span className="font-mono text-neon-green">{tech.count.toLocaleString()}</span>
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
                          <th className="text-left py-3 px-4 text-text-secondary text-sm font-medium">Command</th>
                          <th className="text-left py-3 px-4 text-text-secondary text-sm font-medium">Intent</th>
                          <th className="text-left py-3 px-4 text-text-secondary text-sm font-medium">MITRE</th>
                          <th className="text-center py-3 px-4 text-text-secondary text-sm font-medium">Risk</th>
                          <th className="text-right py-3 px-4 text-text-secondary text-sm font-medium">Count</th>
                          <th className="text-right py-3 px-4 text-text-secondary text-sm font-medium">IPs</th>
                        </tr>
                      </thead>
                      <tbody>
                        {commandExplorer?.commands?.slice(0, 100).map((cmd, index) => {
                          const riskColors: Record<string, string> = {
                            critical: 'bg-neon-red text-white',
                            high: 'bg-neon-orange text-bg-primary',
                            medium: 'bg-neon-yellow text-bg-primary',
                            low: 'bg-bg-hover text-text-secondary'
                          };
                          return (
                            <tr key={index} className="border-b border-bg-hover hover:bg-bg-secondary transition-colors">
                              <td className="py-3 px-4">
                                <code className="font-mono text-sm text-neon-green break-all">{cmd.command.length > 80 ? cmd.command.slice(0, 80) + '...' : cmd.command}</code>
                              </td>
                              <td className="py-3 px-4">
                                <div className="text-sm text-text-primary">{cmd.intent.replace('_', ' ')}</div>
                                <div className="text-xs text-text-muted">{cmd.description}</div>
                              </td>
                              <td className="py-3 px-4">
                                {cmd.mitre ? (
                                  <span className="font-mono text-xs text-neon-blue">{cmd.mitre.split(' - ')[0]}</span>
                                ) : (
                                  <span className="text-text-muted">-</span>
                                )}
                              </td>
                              <td className="py-3 px-4 text-center">
                                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${riskColors[cmd.risk]}`}>
                                  {cmd.risk}
                                </span>
                              </td>
                              <td className="py-3 px-4 text-right font-mono text-sm">{cmd.count.toLocaleString()}</td>
                              <td className="py-3 px-4 text-right font-mono text-sm text-text-muted">{cmd.unique_ips}</td>
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
