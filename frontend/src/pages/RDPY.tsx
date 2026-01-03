import { useCallback, useMemo } from 'react';
import { BarChart2, Clock, Map, Monitor, Key, TrendingUp, Users, Activity, Shield, Globe } from 'lucide-react';
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
import HoneypotPorts from '../components/HoneypotPorts';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { RDPYSession, RDPYCredential, GeoPoint } from '../types';

const COLORS = ['#bf00ff', '#39ff14', '#00d4ff', '#ff6600', '#ff3366'];

export default function RDPY() {
  const { timeRange, setTimeRange } = useTimeRange('24h');

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: sessions, loading: sessionsLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYSessions(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentials, loading: credentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYCredentials(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: connectionPatterns, loading: connectionPatternsLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYConnectionPatterns(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: attackVelocity, loading: attackVelocityLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYAttackVelocity(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: usernameAnalysis, loading: usernameAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYUsernameAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: domainAnalysis, loading: domainAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYDomainAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: hourlyHeatmap, loading: hourlyHeatmapLoading } = useApiWithRefresh(
    useCallback(() => api.getRDPYHourlyHeatmap(timeRange), [timeRange]),
    [timeRange]
  );

  // Process heatmap data for visualization
  const heatmapGrid = useMemo(() => {
    if (!hourlyHeatmap?.heatmap) return [];
    const maxCount = Math.max(...hourlyHeatmap.heatmap.map(h => h.count), 1);
    return hourlyHeatmap.heatmap.map(h => ({
      ...h,
      intensity: h.count / maxCount,
    }));
  }, [hourlyHeatmap]);

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const sessionColumns = [
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: RDPYSession) => <IPLink ip={item.src_ip} />,
    },
    {
      key: 'username',
      header: 'Username',
      render: (item: RDPYSession) => (
        <span className="font-mono text-neon-purple">{item.username || 'N/A'}</span>
      ),
    },
    {
      key: 'domain',
      header: 'Domain',
      render: (item: RDPYSession) => (
        <span className="text-text-secondary">{item.domain || 'N/A'}</span>
      ),
    },
    {
      key: 'timestamp',
      header: 'Time',
      render: (item: RDPYSession) => (
        <span className="text-text-secondary text-sm">{formatTimestamp(item.timestamp)}</span>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (item: RDPYSession) => (
        <span className="text-text-secondary">{item.country || 'Unknown'}</span>
      ),
    },
  ];

  const credentialColumns = [
    {
      key: 'username',
      header: 'Username',
      render: (item: RDPYCredential) => (
        <span className="font-mono text-neon-purple">{item.username}</span>
      ),
    },
    {
      key: 'domain',
      header: 'Domain',
      render: (item: RDPYCredential) => (
        <span className="font-mono text-neon-blue">{item.domain || 'N/A'}</span>
      ),
    },
    {
      key: 'count',
      header: 'Attempts',
      render: (item: RDPYCredential) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
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
            <StatsCard title="Total Connections" value={stats?.total_events || 0} color="purple" loading={statsLoading} />
            <StatsCard title="Unique Attackers" value={stats?.unique_ips || 0} color="blue" loading={statsLoading} />
            <StatsCard title="Unique Usernames" value={credentials?.length || 0} color="green" loading={credentialsLoading} />
            <HoneypotPorts honeypot="rdpy" />
          </div>

          <Card>
            <CardHeader title="Connection Timeline" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorRDPY" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#bf00ff" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#bf00ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#bf00ff" fill="url(#colorRDPY)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Recent Sessions" icon={<Monitor className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable columns={sessionColumns} data={sessions || []} loading={sessionsLoading} emptyMessage="No RDP sessions found" />
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
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader title="Top Credentials" />
            <CardContent className="p-0">
              <DataTable columns={credentialColumns} data={credentials || []} loading={credentialsLoading} emptyMessage="No credentials found" />
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Username Distribution" />
            <CardContent>
              {credentialsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={credentials?.slice(0, 10) || []} layout="vertical" margin={{ left: 80 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis type="number" stroke="#888888" />
                      <YAxis type="category" dataKey="username" stroke="#888888" tick={{ fill: '#888888', fontSize: 11 }} width={80} />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Bar dataKey="count" fill="#bf00ff" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'username-analysis',
      label: 'Username Categories',
      icon: <Shield className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {usernameAnalysisLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-blue">{usernameAnalysis?.total_attempts?.toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Total Attempts</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{usernameAnalysis?.unique_usernames || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Unique Usernames</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{usernameAnalysis?.categories?.admin?.percentage || 0}%</div>
                  <div className="text-xs text-text-secondary mt-1">Admin Accounts</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{usernameAnalysis?.categories?.service?.percentage || 0}%</div>
                  <div className="text-xs text-text-secondary mt-1">Service Accounts</div>
                </div>
              </>
            )}
          </div>

          {/* Category Distribution Chart */}
          <Card>
            <CardHeader title="Username Category Distribution" subtitle="Types of accounts targeted" icon={<Users className="w-5 h-5" />} />
            <CardContent>
              {usernameAnalysisLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Admin', value: usernameAnalysis?.categories?.admin?.count || 0, fill: '#ff3366' },
                          { name: 'Default', value: usernameAnalysis?.categories?.default?.count || 0, fill: '#39ff14' },
                          { name: 'Service', value: usernameAnalysis?.categories?.service?.count || 0, fill: '#00d4ff' },
                          { name: 'Domain', value: usernameAnalysis?.categories?.domain?.count || 0, fill: '#ff6600' },
                          { name: 'Personal', value: usernameAnalysis?.categories?.personal?.count || 0, fill: '#bf00ff' },
                        ].filter(d => d.value > 0)}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={80}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                        formatter={(value: number) => [value.toLocaleString(), 'Attempts']}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Top Usernames by Category */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Admin Accounts */}
            <Card>
              <CardHeader title="Admin Accounts" subtitle="Privileged account attempts" />
              <CardContent>
                {usernameAnalysisLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {usernameAnalysis?.categories?.admin?.top_usernames?.map((u, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded">
                        <code className="text-sm text-neon-red font-mono">{u.username}</code>
                        <span className="text-xs text-text-secondary">{u.count}</span>
                      </div>
                    ))}
                    {(!usernameAnalysis?.categories?.admin?.top_usernames?.length) && (
                      <p className="text-text-muted text-center py-2">No admin accounts detected</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Service Accounts */}
            <Card>
              <CardHeader title="Service Accounts" subtitle="System/service accounts" />
              <CardContent>
                {usernameAnalysisLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {usernameAnalysis?.categories?.service?.top_usernames?.map((u, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded">
                        <code className="text-sm text-neon-blue font-mono">{u.username}</code>
                        <span className="text-xs text-text-secondary">{u.count}</span>
                      </div>
                    ))}
                    {(!usernameAnalysis?.categories?.service?.top_usernames?.length) && (
                      <p className="text-text-muted text-center py-2">No service accounts detected</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Default/Test Accounts */}
            <Card>
              <CardHeader title="Default Accounts" subtitle="Common test/guest accounts" />
              <CardContent>
                {usernameAnalysisLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {usernameAnalysis?.categories?.default?.top_usernames?.map((u, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded">
                        <code className="text-sm text-neon-green font-mono">{u.username}</code>
                        <span className="text-xs text-text-secondary">{u.count}</span>
                      </div>
                    ))}
                    {(!usernameAnalysis?.categories?.default?.top_usernames?.length) && (
                      <p className="text-text-muted text-center py-2">No default accounts detected</p>
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
      id: 'domain-analysis',
      label: 'Domain Analysis',
      icon: <Globe className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {domainAnalysisLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-blue">{domainAnalysis?.total_with_domain?.toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Attempts with Domain</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{domainAnalysis?.unique_domains || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Unique Domains</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-lg font-bold text-neon-purple truncate">{domainAnalysis?.summary?.most_targeted_domain || 'N/A'}</div>
                  <div className="text-xs text-text-secondary mt-1">Top Domain</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{domainAnalysis?.enterprise_domains?.length || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Enterprise Domains</div>
                </div>
              </>
            )}
          </div>

          {/* Domain Table */}
          <Card>
            <CardHeader title="Windows Domains Attempted" subtitle="Domains used in RDP attacks" icon={<Globe className="w-5 h-5" />} />
            <CardContent>
              {domainAnalysisLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Domain</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Attempts</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Unique Users</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Sample Usernames</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {domainAnalysis?.domains?.slice(0, 20).map((domain, idx) => (
                        <tr key={idx} className="hover:bg-bg-secondary transition-colors">
                          <td className="px-4 py-2 font-mono text-neon-purple">{domain.domain || '(empty)'}</td>
                          <td className="px-4 py-2 text-right font-mono text-neon-green">{domain.attempt_count.toLocaleString()}</td>
                          <td className="px-4 py-2 text-right text-text-secondary">{domain.unique_usernames}</td>
                          <td className="px-4 py-2">
                            <div className="flex gap-1 flex-wrap">
                              {domain.sample_usernames.slice(0, 3).map((u, i) => (
                                <span key={i} className="px-2 py-0.5 text-xs bg-bg-secondary text-text-secondary rounded">{u}</span>
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

          {/* Session Heatmap */}
          <Card>
            <CardHeader 
              title="Attack Pattern Heatmap" 
              subtitle={`Peak: ${hourlyHeatmap?.peak_day || 'N/A'} at ${hourlyHeatmap?.peak_hour || 0}:00 (${hourlyHeatmap?.peak_count || 0} attacks)`}
              icon={<Clock className="w-5 h-5" />} 
            />
            <CardContent>
              {hourlyHeatmapLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <div className="min-w-[600px]">
                    {/* Hours header */}
                    <div className="flex gap-1 mb-1 ml-20">
                      {Array.from({ length: 24 }, (_, i) => (
                        <div key={i} className="w-5 text-center text-xs text-text-muted">{i}</div>
                      ))}
                    </div>
                    {/* Days */}
                    {['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map((day, dayIdx) => (
                      <div key={day} className="flex items-center gap-1 mb-1">
                        <div className="w-20 text-xs text-text-secondary text-right pr-2">{day.slice(0, 3)}</div>
                        {Array.from({ length: 24 }, (_, hour) => {
                          const cell = heatmapGrid.find(h => h.day_index === dayIdx && h.hour === hour);
                          const intensity = cell?.intensity || 0;
                          const bgColor = intensity === 0 
                            ? 'bg-bg-secondary' 
                            : `bg-neon-purple`;
                          return (
                            <div 
                              key={hour} 
                              className={`w-5 h-5 rounded-sm ${bgColor} transition-opacity`}
                              style={{ opacity: intensity === 0 ? 0.3 : 0.3 + (intensity * 0.7) }}
                              title={`${day} ${hour}:00 - ${cell?.count || 0} attacks`}
                            />
                          );
                        })}
                      </div>
                    ))}
                    {/* Legend */}
                    <div className="flex items-center gap-2 mt-4 justify-center text-xs text-text-muted">
                      <span>Less</span>
                      <div className="w-4 h-4 bg-neon-purple opacity-30 rounded-sm" />
                      <div className="w-4 h-4 bg-neon-purple opacity-50 rounded-sm" />
                      <div className="w-4 h-4 bg-neon-purple opacity-70 rounded-sm" />
                      <div className="w-4 h-4 bg-neon-purple opacity-100 rounded-sm" />
                      <span>More</span>
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
      id: 'map',
      label: 'Geographic',
      icon: <Map className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Connection Origins" />
          <CardContent>
            {geoLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={geo?.data?.slice(0, 6) || []} dataKey="count" nameKey="country" cx="50%" cy="50%" outerRadius={80} label>
                        {geo?.data?.slice(0, 6).map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-2">
                  {geo?.data?.slice(0, 12).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-purple">{item.count.toLocaleString()}</span>
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
      id: 'analytics',
      label: 'Analytics',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-3">
                  <Activity className="w-8 h-8 text-neon-purple" />
                  <div>
                    <div className="text-2xl font-display font-bold text-neon-purple">
                      {connectionPatterns?.summary?.total_connections?.toLocaleString() || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Total Connections</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-3">
                  <Users className="w-8 h-8 text-neon-green" />
                  <div>
                    <div className="text-2xl font-display font-bold text-neon-green">
                      {connectionPatterns?.summary?.unique_sources?.toLocaleString() || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Unique Sources</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-3">
                  <TrendingUp className="w-8 h-8 text-neon-orange" />
                  <div>
                    <div className="text-2xl font-display font-bold text-neon-orange">
                      {connectionPatterns?.summary?.repeat_attacker_count || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Repeat Attackers (3+)</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-3">
                  <Clock className="w-8 h-8 text-neon-blue" />
                  <div>
                    <div className="text-sm font-mono text-neon-blue">
                      {attackVelocity?.peak_hour ? new Date(attackVelocity.peak_hour).toLocaleTimeString() : 'N/A'}
                    </div>
                    <div className="text-xs text-text-secondary">Peak Hour ({attackVelocity?.peak_connections || 0} conn)</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Attack Velocity */}
          <Card>
            <CardHeader 
              title="Attack Velocity Over Time" 
              subtitle="Connection rate and unique attackers"
              icon={<Activity className="w-5 h-5" />}
            />
            <CardContent>
              {attackVelocityLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={attackVelocity?.velocity || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis 
                        dataKey="timestamp" 
                        stroke="#888888" 
                        tick={{ fill: '#888888', fontSize: 10 }}
                        tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit' })}
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
                      <Line type="monotone" dataKey="connections" stroke="#bf00ff" strokeWidth={2} dot={false} name="Connections" />
                      <Line type="monotone" dataKey="unique_ips" stroke="#39ff14" strokeWidth={2} dot={false} name="Unique IPs" />
                      <Legend />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Repeat Attackers */}
            <Card>
              <CardHeader 
                title="Repeat Attackers" 
                subtitle="IPs with multiple connection attempts"
                icon={<Users className="w-5 h-5" />}
              />
              <CardContent>
                {connectionPatternsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {connectionPatterns?.repeat_attackers?.slice(0, 10).map((attacker, index) => (
                      <div key={attacker.ip} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                        <div className="flex items-center gap-3">
                          <span className="w-6 h-6 flex items-center justify-center rounded-full bg-neon-purple/20 text-neon-purple text-xs font-bold">
                            {index + 1}
                          </span>
                          <div>
                            <IPLink ip={attacker.ip} />
                            <div className="text-xs text-text-muted mt-0.5">
                              {attacker.active_hours} active hours | {attacker.intensity}/hr intensity
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="font-mono text-neon-green">{attacker.connection_count}</div>
                          <div className="text-xs text-text-muted">connections</div>
                        </div>
                      </div>
                    ))}
                    {(!connectionPatterns?.repeat_attackers || connectionPatterns.repeat_attackers.length === 0) && (
                      <div className="text-center py-8 text-text-secondary">No repeat attackers detected</div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Country Distribution */}
            <Card>
              <CardHeader 
                title="Attack Origins" 
                subtitle="Countries targeting RDP"
                icon={<Map className="w-5 h-5" />}
              />
              <CardContent>
                {connectionPatternsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={connectionPatterns?.countries?.slice(0, 8) || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                        <YAxis 
                          type="category" 
                          dataKey="country" 
                          stroke="#888888" 
                          tick={{ fill: '#888888', fontSize: 10 }} 
                          width={80}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                        />
                        <Bar dataKey="count" fill="#bf00ff" radius={[0, 4, 4, 0]} />
                      </BarChart>
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
          <h2 className="text-xl font-display font-semibold text-neon-purple">RDPY RDP Honeypot</h2>
          <p className="text-sm text-text-secondary mt-1">Remote Desktop Protocol honeypot</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />
    </div>
  );
}

