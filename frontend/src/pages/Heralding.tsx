import { useCallback } from 'react';
import { BarChart2, Clock, Map, Key, Network, TrendingUp, Zap } from 'lucide-react';
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
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { HeraldingCredential, HeraldingProtocolStats, GeoPoint } from '../types';

const COLORS = ['#ff3366', '#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ffff00'];

export default function Heralding() {
  const { timeRange, setTimeRange } = useTimeRange('24h');

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentials, loading: credentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentials(timeRange), [timeRange]),
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

  const formatTimestamp = (timestamp: string) => {
    try {
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
        <span className="font-mono text-neon-red uppercase">{item.protocol}</span>
      ),
    },
    {
      key: 'username',
      header: 'Username',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-blue">{item.username}</span>
      ),
    },
    {
      key: 'password',
      header: 'Password',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-orange">{item.password}</span>
      ),
    },
    {
      key: 'count',
      header: 'Attempts',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
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
                        <linearGradient id="colorHeralding" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff3366" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#ff3366" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#ff3366" fill="url(#colorHeralding)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Protocols" icon={<Network className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable columns={protocolColumns} data={protocols || []} loading={protocolsLoading} emptyMessage="No protocols found" />
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
          <Card>
            <CardHeader title="Top Credentials by Protocol" subtitle="Username/password combinations attempted" />
            <CardContent className="p-0">
              <DataTable columns={credentialColumns} data={credentials || []} loading={credentialsLoading} emptyMessage="No credentials found" />
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'protocols',
      label: 'Protocols',
      icon: <Network className="w-4 h-4" />,
      content: (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card>
            <CardHeader title="Protocol Distribution" />
            <CardContent>
              {protocolsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={protocols || []} dataKey="count" nameKey="protocol" cx="50%" cy="50%" outerRadius={80} label>
                        {protocols?.map((_, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Protocol Activity" />
            <CardContent>
              {protocolsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={protocols || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="protocol" stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Bar dataKey="count" fill="#ff3366" radius={[4, 4, 0, 0]} />
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
      id: 'map',
      label: 'Geographic',
      icon: <Map className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Attack Origins" />
          <CardContent>
            {geoLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="space-y-2">
                {geo?.data?.slice(0, 15).map((item: GeoPoint, index: number) => (
                  <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                    <div className="flex items-center">
                      <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                      <span className="text-text-primary">{item.country}</span>
                    </div>
                    <span className="font-mono text-neon-red">{item.count.toLocaleString()}</span>
                  </div>
                ))}
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
          {/* Protocol Detailed Stats */}
          <Card>
            <CardHeader title="Protocol Detailed Statistics" subtitle="Per-protocol metrics and performance" icon={<Network className="w-5 h-5" />} />
            <CardContent>
              {protocolDetailsLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-text-secondary border-b border-bg-hover">
                        <th className="text-left py-2 px-3">Protocol</th>
                        <th className="text-right py-2 px-3">Sessions</th>
                        <th className="text-right py-2 px-3">Unique IPs</th>
                        <th className="text-right py-2 px-3">Avg Duration</th>
                        <th className="text-right py-2 px-3">Total Attempts</th>
                        <th className="text-right py-2 px-3">Avg Attempts</th>
                        <th className="text-left py-2 px-3">Ports</th>
                      </tr>
                    </thead>
                    <tbody>
                      {protocolDetails?.protocols?.map((p) => (
                        <tr key={p.protocol} className="border-b border-bg-hover hover:bg-bg-hover">
                          <td className="py-2 px-3 font-medium text-neon-red">{p.protocol.toUpperCase()}</td>
                          <td className="py-2 px-3 text-right font-mono">{p.sessions.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right font-mono text-neon-green">{p.unique_ips.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right text-text-secondary">{p.avg_duration}s</td>
                          <td className="py-2 px-3 text-right font-mono text-neon-blue">{p.total_auth_attempts.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right text-text-secondary">{p.avg_auth_attempts}</td>
                          <td className="py-2 px-3">
                            <div className="flex gap-1">
                              {p.ports.slice(0, 3).map((port) => (
                                <span key={port} className="px-2 py-0.5 bg-bg-secondary rounded text-xs">{port}</span>
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

