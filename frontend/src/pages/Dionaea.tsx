import { useState, useCallback } from 'react';
import { BarChart2, Clock, Map, Server, TrendingUp, Crosshair, List, ChevronLeft, ChevronRight, Network } from 'lucide-react';
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
import LoadingSpinner from '../components/LoadingSpinner';
import HoneypotPorts from '../components/HoneypotPorts';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { DionaeaPortStats, GeoPoint } from '../types';

const COLORS = ['#00d4ff', '#39ff14', '#ff6600', '#bf00ff', '#ff3366', '#ffff00'];

export default function Dionaea() {
  const { timeRange, setTimeRange } = useTimeRange('24h');
  
  // Pagination state for all connections
  const [connPage, setConnPage] = useState(1);
  const [portFilter, setPortFilter] = useState<number | undefined>(undefined);
  const [ipFilter, setIpFilter] = useState('');
  const connLimit = 50;

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

  const { data: ports, loading: portsLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaPorts(timeRange), [timeRange]),
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

  const connOffset = (connPage - 1) * connLimit;
  const { data: allConnections, loading: allConnectionsLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaAllConnections(
      timeRange, 
      connOffset, 
      connLimit, 
      { port: portFilter, srcIp: ipFilter || undefined }
    ), [timeRange, connOffset, connLimit, portFilter, ipFilter]),
    [timeRange, connOffset, portFilter, ipFilter]
  );

  const totalConnPages = Math.ceil((allConnections?.total || 0) / connLimit);

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

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
                title="Targeted Ports"
                value={ports?.length || 0}
                color="orange"
                loading={portsLoading}
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
      id: 'all-connections',
      label: 'All Connections',
      icon: <List className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader 
            title="All Connections" 
            subtitle={`Total: ${allConnections?.total?.toLocaleString() || 0} connections`} 
            icon={<Network className="w-5 h-5" />} 
          />
          <CardContent>
            {/* Filters */}
            <div className="flex flex-wrap items-center gap-3 mb-4 p-3 bg-bg-secondary rounded-lg">
              <div className="flex items-center gap-2">
                <label className="text-xs text-text-muted">Port:</label>
                <select
                  value={portFilter || ''}
                  onChange={(e) => {
                    setPortFilter(e.target.value ? parseInt(e.target.value) : undefined);
                    setConnPage(1);
                  }}
                  className="bg-bg-card border border-bg-hover rounded px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-neon-blue"
                >
                  <option value="">All Ports</option>
                  <option value="21">21 (FTP)</option>
                  <option value="22">22 (SSH)</option>
                  <option value="23">23 (Telnet)</option>
                  <option value="80">80 (HTTP)</option>
                  <option value="443">443 (HTTPS)</option>
                  <option value="445">445 (SMB)</option>
                  <option value="1433">1433 (MSSQL)</option>
                  <option value="3306">3306 (MySQL)</option>
                  <option value="5060">5060 (SIP)</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <label className="text-xs text-text-muted">IP:</label>
                <input
                  type="text"
                  value={ipFilter}
                  onChange={(e) => {
                    setIpFilter(e.target.value);
                    setConnPage(1);
                  }}
                  placeholder="Filter by IP"
                  className="bg-bg-card border border-bg-hover rounded px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-neon-blue w-36"
                />
              </div>

              {(portFilter || ipFilter) && (
                <button
                  onClick={() => {
                    setPortFilter(undefined);
                    setIpFilter('');
                    setConnPage(1);
                  }}
                  className="text-xs text-neon-red hover:underline"
                >
                  Reset Filters
                </button>
              )}
            </div>

            {allConnectionsLoading ? (
              <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Time</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Source</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Service</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Component</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Message</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {allConnections?.connections?.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="px-4 py-6 text-center text-sm text-text-muted">
                            No connections found
                          </td>
                        </tr>
                      ) : (
                        allConnections?.connections?.map((conn) => (
                          <tr key={String(conn.id)} className="hover:bg-bg-secondary transition-colors">
                            <td className="px-4 py-3 whitespace-nowrap text-sm text-text-primary">
                              {new Date(String(conn.timestamp)).toLocaleString()}
                            </td>
                            <td className="px-4 py-3">
                              <div className="text-sm font-mono text-neon-green">{String(conn.src_ip)}</div>
                              {conn.country ? (
                                <div className="text-xs text-text-muted">{String(conn.country)}</div>
                              ) : null}
                            </td>
                            <td className="px-4 py-3">
                              <span className="px-2 py-1 text-xs font-medium bg-neon-blue/20 text-neon-blue rounded">
                                {String(conn.service)}
                              </span>
                              <div className="text-xs text-text-muted mt-1">Port {String(conn.dst_port)}</div>
                            </td>
                            <td className="px-4 py-3">
                              <span className="text-sm text-text-secondary font-mono">{String(conn.component)}</span>
                            </td>
                            <td className="px-4 py-3">
                              <span className="text-xs text-text-muted truncate max-w-xs block" title={String(conn.message)}>
                                {String(conn.message).slice(0, 60)}...
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {(allConnections?.total || 0) > connLimit && (
                  <div className="flex items-center justify-between mt-4 text-sm text-text-secondary">
                    <span>
                      Showing {connOffset + 1} - {Math.min(connOffset + connLimit, allConnections?.total || 0)} of {allConnections?.total?.toLocaleString()}
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setConnPage(1)}
                        disabled={connPage === 1}
                        className="px-3 py-1 rounded bg-bg-card hover:bg-bg-hover disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        First
                      </button>
                      <button
                        onClick={() => setConnPage(p => Math.max(1, p - 1))}
                        disabled={connPage === 1}
                        className="p-2 rounded bg-bg-card hover:bg-bg-hover disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <ChevronLeft className="w-4 h-4" />
                      </button>
                      <span className="px-3 py-1">Page {connPage} of {totalConnPages}</span>
                      <button
                        onClick={() => setConnPage(p => Math.min(totalConnPages, p + 1))}
                        disabled={connPage === totalConnPages}
                        className="p-2 rounded bg-bg-card hover:bg-bg-hover disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => setConnPage(totalConnPages)}
                        disabled={connPage === totalConnPages}
                        className="px-3 py-1 rounded bg-bg-card hover:bg-bg-hover disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        Last
                      </button>
                    </div>
                  </div>
                )}
              </>
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

