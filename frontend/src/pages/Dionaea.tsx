import { useState, useCallback } from 'react';
import { BarChart2, Clock, Map, Server, TrendingUp, Crosshair, List, ChevronLeft, ChevronRight, Network, Globe, Users, Activity, Shield } from 'lucide-react';
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
import LoadingSpinner from '../components/LoadingSpinner';
import HoneypotPorts from '../components/HoneypotPorts';
import HoneypotMap from '../components/HoneypotMap';
import IPLink from '../components/IPLink';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { DionaeaPortStats, GeoPoint } from '../types';

const COLORS = ['#00d4ff', '#39ff14', '#ff6600', '#bf00ff', '#ff3366', '#ffff00'];
const PORT_COLORS = [
  '#00d4ff', // cyan
  '#39ff14', // green  
  '#ff6600', // orange
  '#bf00ff', // purple
  '#ff3366', // red
  '#ffff00', // yellow
  '#00ff88', // mint
  '#ff00ff', // magenta
  '#00ffff', // aqua
  '#ffd700', // gold
];

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

  const { data: portTimeline, loading: portTimelineLoading } = useApiWithRefresh(
    useCallback(() => api.getDionaeaPortTimeline(timeRange), [timeRange]),
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

  // Port name mapping
  const portNames: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP',
    110: 'POP3', 135: 'MSRPC', 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB',
    1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 1900: 'UPnP', 3306: 'MySQL',
    3389: 'RDP', 5060: 'SIP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Alt', 11211: 'Memcached', 27017: 'MongoDB',
  };

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Stats Row */}
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
                title="Exposed Ports"
                value={stats?.exposed_ports || 15}
                color="orange"
                loading={statsLoading}
              />
            </div>
            <HoneypotPorts honeypot="dionaea" />
          </div>

          {/* Event Timeline */}
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

          {/* Port Activity Timeline */}
          <Card>
            <CardHeader 
              title="Port Activity Timeline" 
              subtitle="Events over time by targeted port"
              icon={<Server className="w-5 h-5" />} 
            />
            <CardContent>
              {portTimelineLoading ? (
                <div className="h-80 flex items-center justify-center">
                  <LoadingSpinner />
                </div>
              ) : (
                <>
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={portTimeline?.timeline || []}>
                        <defs>
                          {portTimeline?.ports?.map((port, index) => (
                            <linearGradient key={port.port} id={`colorPort${port.port}`} x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor={PORT_COLORS[index % PORT_COLORS.length]} stopOpacity={0.4} />
                              <stop offset="95%" stopColor={PORT_COLORS[index % PORT_COLORS.length]} stopOpacity={0} />
                            </linearGradient>
                          ))}
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} 
                          labelFormatter={formatTimestamp}
                        />
                        <Legend />
                        {portTimeline?.ports?.map((port, index) => (
                          <Area 
                            key={port.port}
                            type="monotone" 
                            dataKey={port.label} 
                            name={port.label}
                            stroke={PORT_COLORS[index % PORT_COLORS.length]} 
                            fill={`url(#colorPort${port.port})`}
                            strokeWidth={2}
                            stackId="1"
                          />
                        ))}
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Port Distribution - Integrated from separate tab */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Pie Chart */}
            <Card>
              <CardHeader title="Port Distribution" subtitle="Attack share by targeted port" icon={<Server className="w-5 h-5" />} />
              <CardContent>
                {portsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={ports?.slice(0, 8).map((p: DionaeaPortStats) => ({
                            name: portNames[p.port] || `Port ${p.port}`,
                            value: p.count,
                            port: p.port,
                          })) || []}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={90}
                          paddingAngle={2}
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        >
                          {ports?.slice(0, 8).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={PORT_COLORS[index % PORT_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                          formatter={(value: number) => [value.toLocaleString(), 'Connections']}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Port List */}
            <Card>
              <CardHeader title="All Exposed Ports" subtitle={`${stats?.exposed_ports || 15} ports configured, ${stats?.attacked_ports || 0} attacked`} />
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {ports?.map((port: DionaeaPortStats, index: number) => {
                    const maxCount = ports[0]?.count || 1;
                    const percentage = port.count > 0 ? (port.count / maxCount) * 100 : 0;
                    const isAttacked = port.count > 0;
                    return (
                      <div key={port.port} className={`group ${!isAttacked ? 'opacity-50' : ''}`}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <div 
                              className="w-3 h-3 rounded-full flex-shrink-0"
                              style={{ backgroundColor: isAttacked ? PORT_COLORS[index % PORT_COLORS.length] : '#555' }}
                            />
                            <span className="text-sm font-medium text-text-primary">
                              {portNames[port.port] || `Port ${port.port}`}
                            </span>
                            <span className="text-xs text-text-muted">({port.port})</span>
                            {!isAttacked && <span className="text-xs text-yellow-500/70 ml-2">no attacks</span>}
                          </div>
                          <span className="font-mono text-sm text-neon-blue">{port.count.toLocaleString()}</span>
                        </div>
                        <div className="h-1.5 bg-bg-hover rounded-full overflow-hidden">
                          <div 
                            className="h-full rounded-full transition-all duration-500"
                            style={{ 
                              width: `${Math.max(percentage, isAttacked ? 0 : 2)}%`,
                              backgroundColor: isAttacked ? PORT_COLORS[index % PORT_COLORS.length] : '#444',
                            }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </div>

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
                      <div className="text-lg font-mono font-bold text-neon-blue">{item.count.toLocaleString()}</div>
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
      id: 'map',
      label: 'Attack Map',
      icon: <Map className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <HoneypotMap
            data={geo?.data?.map((g: GeoPoint) => ({ country: g.country, count: g.count })) || []}
            title="Dionaea Attack Origins"
            height="450px"
            accentColor="#00d4ff"
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
                      <span className="text-text-muted text-sm w-6">#{index + 1}</span>
                      <span className="text-text-primary font-medium">{item.country}</span>
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
                              <IPLink ip={String(conn.src_ip)} />
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
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-neon-blue" />
                <span className="text-xs text-text-muted">Total Connections</span>
              </div>
              <div className="text-2xl font-display font-bold text-neon-blue">
                {stats?.total_events?.toLocaleString() || 0}
              </div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="flex items-center gap-2 mb-2">
                <Users className="w-4 h-4 text-neon-green" />
                <span className="text-xs text-text-muted">Unique Attackers</span>
              </div>
              <div className="text-2xl font-display font-bold text-neon-green">
                {attackSources?.total_unique_ips?.toLocaleString() || stats?.unique_ips || 0}
              </div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="flex items-center gap-2 mb-2">
                <Server className="w-4 h-4 text-neon-orange" />
                <span className="text-xs text-text-muted">Services Targeted</span>
              </div>
              <div className="text-2xl font-display font-bold text-neon-orange">
                {serviceDistribution?.services?.length || 0}
              </div>
            </div>
            <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
              <div className="flex items-center gap-2 mb-2">
                <Globe className="w-4 h-4 text-neon-purple" />
                <span className="text-xs text-text-muted">Countries</span>
              </div>
              <div className="text-2xl font-display font-bold text-neon-purple">
                {geo?.data?.length || 0}
              </div>
            </div>
          </div>

          {/* Service Distribution & Radar */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Service Attack Distribution" subtitle="Connections vs Unique IPs" icon={<Server className="w-5 h-5" />} />
              <CardContent>
                {serviceDistLoading ? (
                  <div className="h-72 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-72">
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
              <CardHeader title="Attack Surface Radar" subtitle="Service targeting intensity" icon={<Shield className="w-5 h-5" />} />
              <CardContent>
                {serviceDistLoading ? (
                  <div className="h-72 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-72">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart data={serviceDistribution?.services?.slice(0, 8).map(s => ({
                        service: s.service,
                        connections: Math.log10(s.count + 1) * 25,
                        attackers: Math.log10(s.unique_ips + 1) * 25,
                      })) || []}>
                        <PolarGrid stroke="#252532" />
                        <PolarAngleAxis dataKey="service" tick={{ fill: '#888888', fontSize: 10 }} />
                        <PolarRadiusAxis tick={{ fill: '#888888', fontSize: 10 }} />
                        <Radar name="Connections" dataKey="connections" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.3} />
                        <Radar name="Attackers" dataKey="attackers" stroke="#39ff14" fill="#39ff14" fillOpacity={0.3} />
                        <Legend />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                          }}
                        />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Connection Components & Top Countries */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
                            }}
                            formatter={(value: number) => [value.toLocaleString(), 'Events']}
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

            <Card>
              <CardHeader title="Top Attack Countries" subtitle="Geographic distribution of attackers" icon={<Globe className="w-5 h-5" />} />
              <CardContent>
                {geoLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-2 max-h-72 overflow-y-auto">
                    {geo?.data?.slice(0, 10).map((item: GeoPoint, index: number) => {
                      const maxCount = geo?.data?.[0]?.count || 1;
                      const percentage = (item.count / maxCount) * 100;
                      return (
                        <div key={item.country} className="group">
                          <div className="flex items-center justify-between mb-1">
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-text-muted w-5">#{index + 1}</span>
                              <span className="text-sm font-medium text-text-primary">{item.country}</span>
                            </div>
                            <span className="font-mono text-sm text-neon-blue">{item.count.toLocaleString()}</span>
                          </div>
                          <div className="h-1.5 bg-bg-hover rounded-full overflow-hidden">
                            <div 
                              className="h-full rounded-full transition-all duration-500 bg-neon-blue"
                              style={{ width: `${percentage}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Attack Source Diversity Table */}
          <Card>
            <CardHeader 
              title="Attack Source Diversity by Service" 
              subtitle="Detailed breakdown of attackers per targeted service"
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
                        <th className="text-left py-3 px-4">Service</th>
                        <th className="text-right py-3 px-4">Port</th>
                        <th className="text-right py-3 px-4">Unique IPs</th>
                        <th className="text-right py-3 px-4">Connections</th>
                        <th className="text-right py-3 px-4">Avg/IP</th>
                        <th className="text-left py-3 px-4">Top Countries</th>
                      </tr>
                    </thead>
                    <tbody>
                      {attackSources?.attack_sources?.map((source, index) => (
                        <tr key={source.port} className="border-b border-bg-hover/50 hover:bg-bg-hover transition-colors">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <div 
                                className="w-2 h-2 rounded-full"
                                style={{ backgroundColor: PORT_COLORS[index % PORT_COLORS.length] }}
                              />
                              <span className="font-medium text-text-primary">{source.service}</span>
                            </div>
                          </td>
                          <td className="py-3 px-4 text-right font-mono text-neon-blue">{source.port}</td>
                          <td className="py-3 px-4 text-right font-mono text-neon-green">{source.unique_ips.toLocaleString()}</td>
                          <td className="py-3 px-4 text-right text-text-primary">{source.total_connections.toLocaleString()}</td>
                          <td className="py-3 px-4 text-right font-mono text-text-muted">
                            {source.unique_ips > 0 ? (source.total_connections / source.unique_ips).toFixed(1) : '-'}
                          </td>
                          <td className="py-3 px-4">
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

