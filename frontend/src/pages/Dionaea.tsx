import { useCallback } from 'react';
import { BarChart2, Clock, Map, Network, Server, AlertTriangle, TrendingUp, Crosshair } from 'lucide-react';
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
import type { DionaeaProtocolStats, DionaeaPortStats, DionaeaMalware, GeoPoint } from '../types';

const COLORS = ['#00d4ff', '#39ff14', '#ff6600', '#bf00ff', '#ff3366', '#ffff00'];

export default function Dionaea() {
  const { timeRange, setTimeRange } = useTimeRange('24h');

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: protocols, loading: protocolsLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaProtocols(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: ports, loading: portsLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaPorts(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: malware, loading: malwareLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaMalware(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: serviceDistribution, loading: serviceDistLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaServiceDistribution(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: connectionStates, loading: connectionStatesLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaConnectionStates(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: attackSources, loading: attackSourcesLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaAttackSources(timeRange), [timeRange]),
    [timeRange]
  );

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const malwareColumns = [
    {
      key: 'md5',
      header: 'MD5 Hash',
      render: (item: DionaeaMalware) => (
        <span className="font-mono text-xs text-neon-red">{item.md5}</span>
      ),
    },
    {
      key: 'count',
      header: 'Captures',
      render: (item: DionaeaMalware) => (
        <span className="font-mono text-neon-green">{item.count}</span>
      ),
    },
    {
      key: 'first_seen',
      header: 'First Seen',
      render: (item: DionaeaMalware) => (
        <span className="text-text-secondary text-sm">
          {item.first_seen ? new Date(item.first_seen).toLocaleDateString() : 'N/A'}
        </span>
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
              <StatsCard
                title="Total Events"
                value={stats?.total_events || 0}
                color="blue"
                loading={statsLoading}
              />
              <StatsCard
                title="Unique Attackers"
                value={stats?.unique_ips || 0}
                color="green"
                loading={statsLoading}
              />
              <StatsCard
                title="Malware Samples"
                value={malware?.length || 0}
                color="red"
                loading={malwareLoading}
              />
            </div>
            <HoneypotPorts honeypot="dionaea" />
          </div>

          <Card>
            <CardHeader title="Event Timeline" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-64 flex items-center justify-center">
                  <LoadingSpinner />
                </div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorDionaea" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#00d4ff" fill="url(#colorDionaea)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
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
                <div className="h-64 flex items-center justify-center">
                  <LoadingSpinner />
                </div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={protocols || []}
                        dataKey="count"
                        nameKey="protocol"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        label={({ name }) => name}
                      >
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
            <CardHeader title="Protocol Stats" />
            <CardContent>
              <div className="space-y-3">
                {protocols?.map((item: DionaeaProtocolStats, index: number) => (
                  <div key={item.protocol} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                    <div className="flex items-center">
                      <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                      <span className="font-mono text-text-primary uppercase">{item.protocol}</span>
                    </div>
                    <span className="font-mono text-neon-blue">{item.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'ports',
      label: 'Ports',
      icon: <Server className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Targeted Ports" />
          <CardContent>
            {portsLoading ? (
              <div className="h-64 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={ports?.slice(0, 15) || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                    <XAxis dataKey="port" stroke="#888888" />
                    <YAxis stroke="#888888" />
                    <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    <Bar dataKey="count" fill="#00d4ff" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
            <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
              {ports?.slice(0, 8).map((item: DionaeaPortStats) => (
                <div key={item.port} className="p-3 bg-bg-secondary rounded-lg text-center">
                  <div className="font-mono text-lg text-neon-blue">{item.port}</div>
                  <div className="text-xs text-text-secondary">{item.protocol || 'TCP'}</div>
                  <div className="text-sm text-text-primary">{item.count.toLocaleString()}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
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
              <div className="h-64 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="space-y-2">
                {geo?.data?.slice(0, 15).map((item: GeoPoint, index: number) => (
                  <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                    <div className="flex items-center">
                      <span className="text-text-secondary w-6">{index + 1}.</span>
                      <span className="text-text-primary">{item.country}</span>
                    </div>
                    <span className="font-mono text-neon-blue">{item.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'malware',
      label: 'Malware',
      icon: <AlertTriangle className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Captured Malware Samples" subtitle="MD5 hashes of captured payloads" />
          <CardContent className="p-0">
            <DataTable columns={malwareColumns} data={malware || []} loading={malwareLoading} emptyMessage="No malware samples captured" />
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
          {/* Service Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Service Attack Distribution" subtitle="Attacks by targeted service" icon={<Server className="w-5 h-5" />} />
              <CardContent>
                {serviceDistLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={serviceDistribution?.services?.slice(0, 10) || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} />
                        <YAxis 
                          type="category" 
                          dataKey="service" 
                          stroke="#888888" 
                          tick={{ fill: '#888888', fontSize: 11 }} 
                          width={80}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                          formatter={(value: number, name: string) => [value.toLocaleString(), name === 'count' ? 'Connections' : 'Unique IPs']}
                        />
                        <Legend />
                        <Bar dataKey="count" name="Connections" fill="#00d4ff" radius={[0, 4, 4, 0]} />
                        <Bar dataKey="unique_ips" name="Unique IPs" fill="#39ff14" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Connection Components" subtitle="Event types breakdown" icon={<Network className="w-5 h-5" />} />
              <CardContent>
                {connectionStatesLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <>
                    <div className="h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={connectionStates?.components || []}
                            dataKey="count"
                            nameKey="component"
                            cx="50%"
                            cy="50%"
                            innerRadius={40}
                            outerRadius={70}
                            paddingAngle={2}
                          >
                            {connectionStates?.components?.map((_, index) => (
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
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="space-y-2">
                      {connectionStates?.components?.slice(0, 6).map((item, index) => (
                        <div key={item.component} className="flex items-center justify-between text-sm">
                          <div className="flex items-center">
                            <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                            <span className="text-text-primary font-mono">{item.component}</span>
                          </div>
                          <span className="text-text-secondary">{item.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Attack Source Diversity */}
          <Card>
            <CardHeader 
              title="Attack Source Diversity" 
              subtitle={`Total unique attackers: ${attackSources?.total_unique_ips?.toLocaleString() || 0}`} 
              icon={<Crosshair className="w-5 h-5" />} 
            />
            <CardContent>
              {attackSourcesLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-text-secondary border-b border-bg-hover">
                        <th className="text-left py-2 px-3">Service</th>
                        <th className="text-right py-2 px-3">Port</th>
                        <th className="text-right py-2 px-3">Unique IPs</th>
                        <th className="text-right py-2 px-3">Total Connections</th>
                        <th className="text-left py-2 px-3">Top Countries</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attackSources?.attack_sources?.map((source) => (
                        <tr key={source.port} className="border-b border-bg-hover hover:bg-bg-hover">
                          <td className="py-2 px-3 font-medium text-text-primary">{source.service}</td>
                          <td className="py-2 px-3 text-right font-mono text-neon-blue">{source.port}</td>
                          <td className="py-2 px-3 text-right font-mono text-neon-green">{source.unique_ips.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right text-text-secondary">{source.total_connections.toLocaleString()}</td>
                          <td className="py-2 px-3">
                            <div className="flex flex-wrap gap-1">
                              {source.top_countries.slice(0, 3).map((country) => (
                                <span key={country} className="px-2 py-0.5 bg-bg-secondary rounded text-xs text-text-secondary">
                                  {country}
                                </span>
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
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-neon-blue">Dionaea Honeypot</h2>
          <p className="text-sm text-text-secondary mt-1">Multi-protocol malware capture honeypot</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />
    </div>
  );
}

