import { useCallback } from 'react';
import { BarChart2, Clock, Map, Key, Network, TrendingUp, Zap, AlertTriangle, Users, Globe } from 'lucide-react';
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
import LoadingSpinner from '../components/LoadingSpinner';
import HoneypotPorts from '../components/HoneypotPorts';
import HoneypotMap from '../components/HoneypotMap';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { HeraldingCredential, HeraldingProtocolStats, GeoPoint } from '../types';

const COLORS = ['#ff3366', '#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ffff00', '#ff9999', '#99ff99', '#9999ff', '#ffcc00', '#cc99ff', '#00ffcc'];

// Port-specific colors matching the HoneypotPorts component
const PORT_COLORS: Record<string, string> = {
  FTP: '#39ff14',       // Green
  Telnet: '#00d4ff',    // Cyan
  SMTP: '#ff6600',      // Orange
  HTTP: '#bf00ff',      // Purple
  POP3: '#ffff00',      // Yellow
  IMAP: '#ff3366',      // Pink/Red
  HTTPS: '#00ffcc',     // Teal
  IMAPS: '#99ff99',     // Light green
  POP3S: '#9999ff',     // Light blue
  SOCKS5: '#ffcc00',    // Gold
  MySQL: '#cc99ff',     // Light purple
  PostgreSQL: '#ff9999', // Light red
  VNC: '#66ffff',       // Light cyan
};

export default function Heralding() {
  const { timeRange, setTimeRange } = useTimeRange('24h');

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingStats(timeRange), [timeRange]),
    [timeRange]
  );

  // Total attack timeline
  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timelineByPort, loading: timelineByPortLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingTimelineByPort(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentials, loading: credentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentials(timeRange, 100), [timeRange]),
    [timeRange]
  );

  const { data: protocols, loading: protocolsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingProtocols(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: protocolDetails, loading: protocolDetailsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingProtocolDetailedStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: attemptIntensity, loading: attemptIntensityLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingAttemptIntensity(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentialVelocity, loading: credentialVelocityLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentialVelocity(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: bruteForce, loading: bruteForceLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingBruteForceDetection(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentialReuse, loading: credentialReuseLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentialReuse(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: topCredentials, loading: topCredentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingTopCredentials(timeRange, 10), [timeRange]),
    [timeRange]
  );

  const formatTimestamp = (timestamp: string) => {
    try {
      if (timeRange === '7d' || timeRange === '30d') {
        return new Date(timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      }
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const credentialColumns = [
    {
      key: 'protocol',
      header: 'Protocol',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-red uppercase text-sm">{item.protocol}</span>
      ),
    },
    {
      key: 'username',
      header: 'Username',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-blue text-sm">{item.username || '(empty)'}</span>
      ),
    },
    {
      key: 'password',
      header: 'Password',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-orange text-sm">{item.password || '(empty)'}</span>
      ),
    },
    {
      key: 'count',
      header: 'Attempts',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-green font-semibold">{item.count.toLocaleString()}</span>
      ),
    },
  ];

  const protocolColumns = [
    {
      key: 'protocol',
      header: 'Protocol',
      render: (item: HeraldingProtocolStats) => (
        <span className="font-mono text-neon-red uppercase">{item.protocol}</span>
      ),
    },
    {
      key: 'count',
      header: 'Events',
      render: (item: HeraldingProtocolStats) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
      ),
    },
    {
      key: 'unique_ips',
      header: 'Unique IPs',
      render: (item: HeraldingProtocolStats) => (
        <span className="font-mono text-neon-blue">{item.unique_ips.toLocaleString()}</span>
      ),
    },
  ];

  // Calculate total for pie chart
  const totalEvents = protocols?.reduce((sum, p) => sum + p.count, 0) || 0;

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <StatsCard title="Total Events" value={stats?.total_events || 0} color="red" loading={statsLoading} />
              <StatsCard title="Unique Attackers" value={stats?.unique_ips || 0} color="blue" loading={statsLoading} />
              <StatsCard title="Protocols" value={protocols?.length || 0} color="green" loading={protocolsLoading} />
            </div>
            <HoneypotPorts honeypot="heralding" />
          </div>

          {/* Total Attack Timeline */}
          <Card>
            <CardHeader title="Attack Timeline" subtitle="Total authentication events over time" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-72 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-72">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff3366" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#ff3366" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis 
                        dataKey="timestamp" 
                        tickFormatter={formatTimestamp} 
                        stroke="#888888" 
                        tick={{ fontSize: 11 }}
                      />
                      <YAxis 
                        stroke="#888888" 
                        tick={{ fontSize: 11 }}
                        tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(1)}K` : v}
                      />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} 
                        labelFormatter={(label) => new Date(String(label)).toLocaleString()}
                        formatter={(value: number) => [value.toLocaleString(), 'Events']}
                      />
                      <Area
                        type="monotone"
                        dataKey="count"
                        name="Events"
                        stroke="#ff3366"
                        fill="url(#colorEvents)"
                        strokeWidth={2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Event Timeline by Port */}
          <Card>
            <CardHeader title="Events by Protocol" subtitle="Activity breakdown by service" icon={<Network className="w-5 h-5" />} />
            <CardContent>
              {timelineByPortLoading ? (
                <div className="h-80 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineByPort?.data || []}>
                      <defs>
                        {(timelineByPort?.ports || []).map((port, index) => (
                          <linearGradient key={port.name} id={`color${port.name}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={PORT_COLORS[port.name] || COLORS[index % COLORS.length]} stopOpacity={0.3} />
                            <stop offset="95%" stopColor={PORT_COLORS[port.name] || COLORS[index % COLORS.length]} stopOpacity={0} />
                          </linearGradient>
                        ))}
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" tick={{ fontSize: 11 }} />
                      <YAxis stroke="#888888" tick={{ fontSize: 11 }} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} 
                        labelFormatter={(label) => formatTimestamp(String(label))}
                      />
                      <Legend />
                      {(timelineByPort?.ports || []).map((port, index) => (
                        <Area
                          key={port.name}
                          type="monotone"
                          dataKey={port.name}
                          name={`${port.name} (${port.port})`}
                          stroke={PORT_COLORS[port.name] || COLORS[index % COLORS.length]}
                          fill={`url(#color${port.name})`}
                          strokeWidth={2}
                          stackId="1"
                        />
                      ))}
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Protocol Distribution Charts - Improved Readability */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Protocol Pie Chart with Side Legend */}
            <Card>
              <CardHeader title="Protocol Share" subtitle="Distribution of attack events" icon={<Network className="w-5 h-5" />} />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-80 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-80 flex">
                    {/* Pie Chart */}
                    <div className="flex-1">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={protocols || []}
                            dataKey="count"
                            nameKey="protocol"
                            cx="50%"
                            cy="50%"
                            innerRadius={50}
                            outerRadius={90}
                            paddingAngle={2}
                          >
                            {(protocols || []).map((_, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                            formatter={(value: number, name: string) => [`${value.toLocaleString()} (${((value / totalEvents) * 100).toFixed(1)}%)`, name]}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    {/* Side Legend */}
                    <div className="w-48 flex flex-col justify-center space-y-2 pl-4">
                      {protocols?.slice(0, 8).map((p, index) => {
                        const percentage = ((p.count / totalEvents) * 100).toFixed(1);
                        return (
                          <div key={p.protocol} className="flex items-center gap-2 text-sm">
                            <div 
                              className="w-3 h-3 rounded-full flex-shrink-0" 
                              style={{ backgroundColor: COLORS[index % COLORS.length] }} 
                            />
                            <span className="text-text-primary font-mono uppercase">{p.protocol}</span>
                            <span className="text-text-secondary ml-auto">{percentage}%</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Protocol Bar Chart - Horizontal with Better Labels */}
            <Card>
              <CardHeader title="Protocol Activity" subtitle="Attack events by protocol" icon={<BarChart2 className="w-5 h-5" />} />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-80 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={protocols || []} layout="vertical" margin={{ left: 10 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis 
                          type="number" 
                          stroke="#888888" 
                          tick={{ fontSize: 11 }}
                          tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(0)}K` : v}
                        />
                        <YAxis 
                          dataKey="protocol" 
                          type="category" 
                          stroke="#888888" 
                          width={70}
                          tick={{ fill: '#ff3366', fontSize: 12, fontFamily: 'monospace' }}
                        />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                          formatter={(value: number) => [value.toLocaleString(), 'Events']}
                        />
                        <Bar 
                          dataKey="count" 
                          fill="#ff3366"
                          radius={[0, 4, 4, 0]}
                        >
                          {(protocols || []).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader title="Protocols" icon={<Network className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable columns={protocolColumns} data={protocols || []} loading={protocolsLoading} emptyMessage="No protocols found" />
            </CardContent>
          </Card>

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
                      <div className="text-lg font-mono font-bold text-neon-red">{item.count.toLocaleString()}</div>
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
          {/* Summary Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-blue">{topCredentials?.total_unique_usernames || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Unique Usernames</div>
            </div>
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-orange">{topCredentials?.total_unique_passwords || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Unique Passwords</div>
            </div>
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-green">{credentials?.length || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Credential Combos</div>
            </div>
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-red">{protocols?.length || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Protocols Targeted</div>
            </div>
          </div>

          {/* Top 10 Usernames and Passwords */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top 10 Usernames */}
            <Card>
              <CardHeader 
                title="Top 10 Usernames" 
                subtitle="Most frequently attempted usernames"
                icon={<Users className="w-5 h-5 text-neon-blue" />}
              />
              <CardContent>
                {topCredentialsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2">
                    {topCredentials?.top_usernames?.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="w-6 h-6 flex items-center justify-center bg-neon-blue/20 text-neon-blue rounded-full text-sm font-bold">
                            {idx + 1}
                          </span>
                          <code className="font-mono text-neon-blue text-sm">{item.username || '(empty)'}</code>
                        </div>
                        <span className="font-mono text-neon-green font-semibold">{item.count.toLocaleString()}</span>
                      </div>
                    ))}
                    {(!topCredentials?.top_usernames?.length) && (
                      <p className="text-text-muted text-center py-8">No usernames found</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top 10 Passwords */}
            <Card>
              <CardHeader 
                title="Top 10 Passwords" 
                subtitle="Most frequently attempted passwords"
                icon={<Key className="w-5 h-5 text-neon-orange" />}
              />
              <CardContent>
                {topCredentialsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2">
                    {topCredentials?.top_passwords?.map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="w-6 h-6 flex items-center justify-center bg-neon-orange/20 text-neon-orange rounded-full text-sm font-bold">
                            {idx + 1}
                          </span>
                          <code className="font-mono text-neon-orange text-sm">{item.password || '(empty)'}</code>
                        </div>
                        <span className="font-mono text-neon-green font-semibold">{item.count.toLocaleString()}</span>
                      </div>
                    ))}
                    {(!topCredentials?.top_passwords?.length) && (
                      <p className="text-text-muted text-center py-8">No passwords found</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* All Credential Combinations - Bigger Table */}
          <Card>
            <CardHeader title="All Credential Combinations" subtitle="Username/password pairs attempted by protocol" />
            <CardContent className="p-0">
              <div className="max-h-[600px] overflow-auto">
                <DataTable 
                  columns={credentialColumns} 
                  data={credentials || []} 
                  loading={credentialsLoading} 
                  emptyMessage="No credentials found" 
                />
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'brute-force',
      label: 'Brute Force',
      icon: <AlertTriangle className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {bruteForceLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{bruteForce?.total_brute_force_ips || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Brute Force IPs</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{bruteForce?.aggressive_attackers || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Aggressive (&gt;50/min)</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{bruteForce?.moderate_attackers || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Moderate (10-50/min)</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{bruteForce?.slow_attackers || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Slow (&lt;10/min)</div>
                </div>
              </>
            )}
          </div>

          {/* Brute Force Attackers Table */}
          <Card>
            <CardHeader title="Brute Force Attackers" subtitle="IPs with rapid credential attempts" icon={<AlertTriangle className="w-5 h-5 text-neon-red" />} />
            <CardContent>
              {bruteForceLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">IP</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Intensity</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Attempts</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Rate/min</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Sessions</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Protocols</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Location</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {bruteForce?.brute_forcers?.slice(0, 25).map((attacker, idx) => {
                        const intensityColors: Record<string, string> = {
                          aggressive: 'text-neon-red bg-neon-red/20',
                          moderate: 'text-neon-orange bg-neon-orange/20',
                          slow: 'text-neon-green bg-neon-green/20',
                        };
                        return (
                          <tr key={idx} className="hover:bg-bg-secondary transition-colors">
                            <td className="px-4 py-2 font-mono text-neon-blue">{attacker.ip}</td>
                            <td className="px-4 py-2">
                              <span className={`px-2 py-1 text-xs rounded ${intensityColors[attacker.intensity] || ''}`}>
                                {attacker.intensity}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-right font-mono text-neon-red">{attacker.total_attempts.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right text-text-secondary">{attacker.attempts_per_minute}</td>
                            <td className="px-4 py-2 text-right text-text-secondary">{attacker.session_count}</td>
                            <td className="px-4 py-2">
                              <div className="flex gap-1 flex-wrap">
                                {attacker.protocols.slice(0, 3).map((proto) => (
                                  <span key={proto} className="px-2 py-0.5 text-xs bg-bg-secondary text-text-primary rounded">{proto}</span>
                                ))}
                              </div>
                            </td>
                            <td className="px-4 py-2 text-sm text-text-secondary">
                              {attacker.geo?.country || 'Unknown'}
                              {attacker.geo?.city && <span className="text-text-muted"> / {attacker.geo.city}</span>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Credential Reuse */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Passwords Used by Multiple IPs" subtitle="Coordinated attack indicator" icon={<Users className="w-5 h-5" />} />
              <CardContent>
                {credentialReuseLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (credentialReuse?.reused_passwords?.length || 0) > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {credentialReuse?.reused_passwords?.slice(0, 15).map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                        <code className="text-sm text-neon-orange font-mono">{item.password}</code>
                        <span className="px-2 py-1 text-xs bg-neon-purple/20 text-neon-purple rounded">
                          {item.ip_count} IPs
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-text-muted text-center py-4">No reused passwords detected</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Usernames Used by Multiple IPs" subtitle="Common target accounts" icon={<Users className="w-5 h-5" />} />
              <CardContent>
                {credentialReuseLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (credentialReuse?.reused_usernames?.length || 0) > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {credentialReuse?.reused_usernames?.slice(0, 15).map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                        <code className="text-sm text-neon-blue font-mono">{item.username}</code>
                        <span className="px-2 py-1 text-xs bg-neon-purple/20 text-neon-purple rounded">
                          {item.ip_count} IPs
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-text-muted text-center py-4">No reused usernames detected</p>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
    {
      id: 'protocols',
      label: 'Protocols',
      icon: <Network className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Protocol Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {protocolDetailsLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{protocolDetails?.protocols?.length || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Protocols Targeted</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{protocolDetails?.protocols?.reduce((sum, p) => sum + p.sessions, 0).toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Total Sessions</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-blue">{protocolDetails?.protocols?.[0]?.protocol?.toUpperCase() || 'N/A'}</div>
                  <div className="text-xs text-text-secondary mt-1">Most Targeted</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{protocolDetails?.protocols?.reduce((sum, p) => sum + p.total_auth_attempts, 0).toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Auth Attempts</div>
                </div>
              </>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Protocol Distribution" subtitle="Breakdown of attack attempts per protocol" />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64 flex">
                    <div className="flex-1">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie data={protocols || []} dataKey="count" nameKey="protocol" cx="50%" cy="50%" innerRadius={40} outerRadius={80}>
                            {protocols?.map((_, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="w-40 flex flex-col justify-center space-y-1">
                      {protocols?.slice(0, 6).map((p, idx) => (
                        <div key={p.protocol} className="flex items-center gap-2 text-xs">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                          <span className="font-mono uppercase">{p.protocol}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Protocol Activity" subtitle="Comparison of attack volume by protocol" />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={protocols || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" />
                        <YAxis type="category" dataKey="protocol" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} width={60} />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#ff3366" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Detailed Protocol Stats */}
          <Card>
            <CardHeader title="Protocol Details" subtitle="Detailed metrics per protocol" icon={<Network className="w-5 h-5" />} />
            <CardContent>
              {protocolDetailsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Protocol</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Sessions</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Unique IPs</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Auth Attempts</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Avg Duration</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Port</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {protocolDetails?.protocols?.map((proto, idx) => {
                        const totalSessions = protocolDetails?.protocols?.reduce((sum, p) => sum + p.sessions, 0) || 1;
                        const percentage = ((proto.sessions / totalSessions) * 100).toFixed(1);
                        return (
                          <tr key={idx} className="hover:bg-bg-secondary transition-colors">
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                                <span className="font-mono text-text-primary uppercase">{proto.protocol}</span>
                                <span className="text-xs text-text-muted">({percentage}%)</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-right font-mono text-neon-red">{proto.sessions.toLocaleString()}</td>
                            <td className="px-4 py-3 text-right font-mono text-neon-blue">{proto.unique_ips}</td>
                            <td className="px-4 py-3 text-right font-mono text-neon-green">{proto.total_auth_attempts.toLocaleString()}</td>
                            <td className="px-4 py-3 text-right font-mono text-text-secondary">{proto.avg_duration.toFixed(1)}s</td>
                            <td className="px-4 py-3 text-right font-mono text-neon-orange">{proto.ports.join(', ')}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
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
            title="Heralding Attack Origins"
            height="450px"
            accentColor="#ff3366"
            loading={geoLoading}
          />
          
          {/* Top Countries List */}
          <Card>
            <CardHeader title="Top Attack Countries" subtitle={`${geo?.data?.length || 0} countries detected`} />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {geo?.data?.slice(0, 12).map((item: GeoPoint, index: number) => (
                  <div key={item.country} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                    <div className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                      <span className="text-text-primary font-medium">{item.country}</span>
                    </div>
                    <span className="font-mono text-neon-red">{item.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'analytics',
      label: 'Analytics',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Protocol Detailed Stats - Fixed Table */}
          <Card>
            <CardHeader title="Protocol Statistics" subtitle="Per-protocol metrics and performance" icon={<Network className="w-5 h-5" />} />
            <CardContent>
              {protocolDetailsLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card sticky top-0">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">Protocol</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase tracking-wider">Sessions</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase tracking-wider">Unique IPs</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase tracking-wider">Avg Duration</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase tracking-wider">Total Attempts</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase tracking-wider">Avg Attempts</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">Ports</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {protocolDetails?.protocols?.map((p, idx) => (
                        <tr key={p.protocol} className="hover:bg-bg-secondary transition-colors">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                              <span className="font-mono font-semibold text-neon-red uppercase">{p.protocol}</span>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-right font-mono">{p.sessions.toLocaleString()}</td>
                          <td className="px-4 py-3 text-right font-mono text-neon-green">{p.unique_ips.toLocaleString()}</td>
                          <td className="px-4 py-3 text-right text-text-secondary">{p.avg_duration}s</td>
                          <td className="px-4 py-3 text-right font-mono text-neon-blue">{p.total_auth_attempts.toLocaleString()}</td>
                          <td className="px-4 py-3 text-right text-text-secondary">{p.avg_auth_attempts}</td>
                          <td className="px-4 py-3">
                            <div className="flex gap-1 flex-wrap">
                              {p.ports.slice(0, 3).map((port) => (
                                <span key={port} className="px-2 py-0.5 bg-bg-secondary text-neon-orange rounded text-xs font-mono">{port}</span>
                              ))}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attempt Intensity */}
            <Card>
              <CardHeader title="Authentication Attempt Intensity" subtitle="Sessions and attempts over time" icon={<Zap className="w-5 h-5" />} />
              <CardContent>
                {attemptIntensityLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={attemptIntensity?.intensity || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis 
                          dataKey="timestamp" 
                          tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                          stroke="#888888"
                          tick={{ fill: '#888888', fontSize: 10 }}
                        />
                        <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                          labelFormatter={(ts) => new Date(ts).toLocaleString()}
                        />
                        <Legend />
                        <Line type="monotone" dataKey="sessions" name="Sessions" stroke="#ff3366" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="total_attempts" name="Auth Attempts" stroke="#39ff14" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="unique_ips" name="Unique IPs" stroke="#00d4ff" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Credential Velocity */}
            <Card>
              <CardHeader 
                title="Credential Brute-Force Velocity" 
                subtitle={`Total attempts: ${credentialVelocity?.total_attempts?.toLocaleString() || 0}`} 
                icon={<Key className="w-5 h-5" />} 
              />
              <CardContent>
                {credentialVelocityLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={credentialVelocity?.velocity || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis 
                          dataKey="timestamp" 
                          tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                          stroke="#888888"
                          tick={{ fill: '#888888', fontSize: 10 }}
                        />
                        <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                          labelFormatter={(ts) => new Date(ts).toLocaleString()}
                          formatter={(value: number, name: string) => [
                            name === 'rate_per_minute' ? `${value}/min` : value.toLocaleString(),
                            name === 'rate_per_minute' ? 'Rate' : 'Attempts'
                          ]}
                        />
                        <Area 
                          type="monotone" 
                          dataKey="rate_per_minute" 
                          stroke="#ff6600" 
                          fill="#ff6600" 
                          fillOpacity={0.3}
                          name="Rate/min"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-neon-red">Heralding Honeypot</h2>
          <p className="text-sm text-text-secondary mt-1">Multi-protocol credential capture honeypot</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />
    </div>
  );
}
