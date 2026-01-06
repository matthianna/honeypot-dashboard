import { useCallback } from 'react';
import { BarChart2, Clock, Map, Monitor, Key, TrendingUp, Users, Activity, Info, Globe } from 'lucide-react';
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
import HoneypotMap from '../components/HoneypotMap';
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
          {/* Info Banner */}
          <div className="flex items-start gap-3 p-4 bg-neon-purple/10 border border-neon-purple/30 rounded-lg">
            <Info className="w-5 h-5 text-neon-purple flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-sm text-text-primary">
                <strong>Note:</strong> RDPY captures connection attempts and metadata. Credentials may be limited depending on how far attackers progress in the RDP handshake.
              </p>
              <p className="text-xs text-text-secondary mt-1">
                This honeypot logs connection sources, usernames, and domains when available.
              </p>
            </div>
          </div>

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
                      <div className="text-lg font-mono font-bold text-neon-purple">{item.count.toLocaleString()}</div>
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
          {/* Info Banner */}
          {(!credentials || credentials.length === 0) && !credentialsLoading && (
            <div className="flex items-start gap-3 p-4 bg-neon-blue/10 border border-neon-blue/30 rounded-lg">
              <Info className="w-5 h-5 text-neon-blue flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm text-text-primary">
                  <strong>Limited Credential Data</strong>
                </p>
                <p className="text-xs text-text-secondary mt-1">
                  RDPY primarily captures connection metadata. Full credential capture requires attackers to progress through the complete RDP authentication handshake, which many automated scanners do not complete.
                </p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Top Credentials" />
              <CardContent className="p-0">
                <DataTable columns={credentialColumns} data={credentials || []} loading={credentialsLoading} emptyMessage="No credentials captured yet" />
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
            title="RDP Attack Origins"
            height="450px"
            accentColor="#bf00ff"
            loading={geoLoading}
          />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Pie Chart */}
            <Card>
              <CardHeader title="Top Countries Distribution" subtitle="Attack share by country" />
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie 
                        data={geo?.data?.slice(0, 6) || []} 
                        dataKey="count" 
                        nameKey="country" 
                        cx="50%" 
                        cy="50%" 
                        outerRadius={80} 
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                        {geo?.data?.slice(0, 6).map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            {/* Country List */}
            <Card>
              <CardHeader title="Attack Countries" subtitle={`${geo?.data?.length || 0} countries detected`} />
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {geo?.data?.slice(0, 12).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary font-medium">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-purple">{item.count.toLocaleString()}</span>
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

