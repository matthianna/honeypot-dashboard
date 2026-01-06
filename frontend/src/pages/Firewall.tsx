import { useCallback, useState } from 'react';
import { BarChart2, Clock, Scan, Users, Server, List, Filter, Eye, ShieldAlert, AlertTriangle, TrendingUp, Target } from 'lucide-react';
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
  Cell,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import TimeRangeSelector from '../components/TimeRangeSelector';
import Tabs from '../components/Tabs';
import DataTable from '../components/DataTable';
import IPLink from '../components/IPLink';
import LoadingSpinner from '../components/LoadingSpinner';
import RawLogModal from '../components/RawLogModal';
import UnexposedPortsAnalysis from '../components/UnexposedPortsAnalysis';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { FirewallBlockedTraffic, PortScanDetection, RepeatOffender } from '../types';

const COLORS = ['#ff3366', '#ff6600', '#ffff00', '#39ff14', '#00d4ff', '#bf00ff'];
const INTERNAL_IPS = ['193.246.121.231', '193.246.121.232', '193.246.121.233'];

export default function Firewall() {
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [selectedInternalIP, setSelectedInternalIP] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<Record<string, unknown> | null>(null);

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: blocked, loading: blockedLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallBlocked(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: portScans, loading: portScansLoading } = useApiWithRefresh(
    useCallback(() => api.getPortScans(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: repeatOffenders, loading: repeatOffendersLoading } = useApiWithRefresh(
    useCallback(() => api.getRepeatOffenders(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: internalHostStats, loading: internalHostLoading } = useApiWithRefresh(
    useCallback(() => selectedInternalIP ? api.getInternalHostStats(selectedInternalIP, timeRange) : Promise.resolve(null), [selectedInternalIP, timeRange]),
    [selectedInternalIP, timeRange]
  );

  const { data: events, loading: eventsLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallEvents(timeRange, 100, actionFilter || undefined), [timeRange, actionFilter]),
    [timeRange, actionFilter]
  );

  const { data: actions } = useApiWithRefresh(
    useCallback(() => api.getFirewallActions(timeRange), [timeRange]),
    [timeRange]
  );

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const formatFullTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch {
      return timestamp;
    }
  };

  const blockedColumns = [
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: FirewallBlockedTraffic) => <IPLink ip={item.src_ip} />,
    },
    {
      key: 'count',
      header: 'Blocked',
      render: (item: FirewallBlockedTraffic) => (
        <span className="font-mono text-neon-red">{item.count.toLocaleString()}</span>
      ),
    },
    {
      key: 'ports',
      header: 'Ports',
      render: (item: FirewallBlockedTraffic) => (
        <span className="text-text-secondary text-sm">{item.ports.slice(0, 5).join(', ')}{item.ports.length > 5 ? '...' : ''}</span>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (item: FirewallBlockedTraffic) => (
        <span className="text-text-secondary">{item.country || 'Unknown'}</span>
      ),
    },
  ];

  // Improved event columns - only show columns with data
  const eventColumns = [
    {
      key: 'timestamp',
      header: 'Time',
      render: (item: Record<string, unknown>) => (
        <span className="text-text-secondary text-sm">{formatFullTimestamp(item.timestamp as string)}</span>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (item: Record<string, unknown>) => {
        const action = item.action as string;
        const actionColors: Record<string, string> = {
          block: 'text-neon-red bg-neon-red/20',
          pass: 'text-neon-green bg-neon-green/20',
          nat: 'text-neon-blue bg-neon-blue/20',
        };
        return (
          <span className={`px-2 py-1 rounded text-xs font-mono uppercase ${actionColors[action] || 'text-text-secondary bg-bg-hover'}`}>
            {action}
          </span>
        );
      },
    },
    {
      key: 'source',
      header: 'Source',
      render: (item: Record<string, unknown>) => {
        const source = item.source as { ip: string; port: number } | undefined;
        if (!source?.ip) return null;
        return (
          <div className="flex items-center gap-1">
            <IPLink ip={source.ip} />
            {source.port && <span className="text-text-muted text-xs">:{source.port}</span>}
          </div>
        );
      },
    },
    {
      key: 'destination',
      header: 'Destination',
      render: (item: Record<string, unknown>) => {
        const dest = item.destination as { ip: string; port: number } | undefined;
        if (!dest?.ip) return null;
        return (
          <span className="font-mono text-sm">
            <span className="text-text-primary">{dest.ip}</span>
            {dest.port && <span className="text-text-muted">:{dest.port}</span>}
          </span>
        );
      },
    },
    {
      key: 'transport',
      header: 'Protocol',
      render: (item: Record<string, unknown>) => {
        const transport = item.transport as string;
        if (!transport) return null;
        return <span className="text-text-secondary text-sm uppercase">{transport}</span>;
      },
    },
    {
      key: 'interface',
      header: 'Interface',
      render: (item: Record<string, unknown>) => {
        const iface = item.interface as string;
        if (!iface) return null;
        return <span className="font-mono text-xs text-text-secondary">{iface}</span>;
      },
    },
    {
      key: 'actions',
      header: '',
      render: (item: Record<string, unknown>) => (
        <button
          onClick={() => setSelectedEvent(item)}
          className="p-2 hover:bg-bg-hover rounded-lg transition-colors text-text-secondary hover:text-neon-yellow"
          title="View raw log"
        >
          <Eye className="w-4 h-4" />
        </button>
      ),
    },
  ];

  // Port scan chart data
  const portScanChartData = (portScans || []).slice(0, 10).map((scan: PortScanDetection, index: number) => ({
    ip: scan.src_ip.length > 15 ? scan.src_ip.substring(0, 12) + '...' : scan.src_ip,
    fullIp: scan.src_ip,
    ports: scan.unique_ports,
    color: COLORS[index % COLORS.length],
    country: scan.country || 'Unknown',
  }));

  // Repeat offender chart data
  const offenderChartData = (repeatOffenders || []).slice(0, 10).map((offender: RepeatOffender, index: number) => ({
    ip: offender.src_ip.length > 15 ? offender.src_ip.substring(0, 12) + '...' : offender.src_ip,
    fullIp: offender.src_ip,
    blocks: offender.total_blocks,
    color: COLORS[index % COLORS.length],
    country: offender.country || 'Unknown',
    ports: offender.targeted_ports.slice(0, 5).join(', '),
  }));

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <StatsCard title="Total Events" value={stats?.total_events || 0} color="yellow" loading={statsLoading} />
            <StatsCard title="Unique IPs" value={stats?.unique_ips || 0} color="blue" loading={statsLoading} />
            <StatsCard title="Port Scanners" value={portScans?.length || 0} color="orange" loading={portScansLoading} />
            <StatsCard title="Repeat Offenders" value={repeatOffenders?.length || 0} color="red" loading={repeatOffendersLoading} />
          </div>

          <Card>
            <CardHeader title="Firewall Event Timeline" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorFirewall" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ffff00" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#ffff00" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#ffff00" fill="url(#colorFirewall)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Actions Distribution */}
          {actions?.actions && actions.actions.length > 0 && (
            <Card>
              <CardHeader title="Action Distribution" icon={<Filter className="w-5 h-5" />} />
              <CardContent>
                <div className="flex flex-wrap gap-4">
                  {actions.actions.map((item) => {
                    const actionColors: Record<string, string> = {
                      block: 'border-neon-red text-neon-red',
                      pass: 'border-neon-green text-neon-green',
                      nat: 'border-neon-blue text-neon-blue',
                    };
                    return (
                      <div
                        key={item.action}
                        className={`px-4 py-3 rounded-lg border ${actionColors[item.action] || 'border-bg-hover text-text-secondary'} bg-bg-secondary`}
                      >
                        <div className="text-2xl font-display font-bold">{item.count.toLocaleString()}</div>
                        <div className="text-sm uppercase">{item.action}</div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader title="Blocked Traffic" icon={<ShieldAlert className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable columns={blockedColumns} data={blocked || []} loading={blockedLoading} emptyMessage="No blocked traffic" />
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'events',
      label: 'Events',
      icon: <List className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader 
            title="Firewall Events" 
            subtitle="Detailed event log with filtering"
            icon={<List className="w-5 h-5" />}
          />
          <CardContent>
            {/* Filters */}
            <div className="flex flex-wrap gap-4 mb-4 pb-4 border-b border-bg-hover">
              <div className="flex items-center space-x-2">
                <Filter className="w-4 h-4 text-text-secondary" />
                <span className="text-sm text-text-secondary">Action:</span>
                <select
                  value={actionFilter}
                  onChange={(e) => setActionFilter(e.target.value)}
                  className="bg-bg-secondary border border-bg-hover rounded-lg px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-neon-yellow"
                >
                  <option value="">All</option>
                  <option value="block">Block</option>
                  <option value="pass">Pass</option>
                  <option value="nat">NAT</option>
                </select>
              </div>
              <div className="text-sm text-text-secondary flex items-center">
                <span className="font-mono text-neon-yellow">{events?.total?.toLocaleString() || 0}</span>
                <span className="ml-1">events found</span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <DataTable 
                columns={eventColumns} 
                data={(events?.events || []).filter((e: Record<string, unknown>) => e.action != null)} 
                loading={eventsLoading} 
                emptyMessage="No events found" 
              />
            </div>
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'port-scans',
      label: 'Port Scans',
      icon: <Scan className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-neon-orange/20">
                    <Scan className="w-6 h-6 text-neon-orange" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-orange">
                      {portScans?.length || 0}
                    </div>
                    <div className="text-sm text-text-secondary">Total Scanners</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-neon-red/20">
                    <Target className="w-6 h-6 text-neon-red" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-red">
                      {portScans?.reduce((sum: number, s: PortScanDetection) => sum + s.unique_ports, 0) || 0}
                    </div>
                    <div className="text-sm text-text-secondary">Total Ports Scanned</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-neon-purple/20">
                    <TrendingUp className="w-6 h-6 text-neon-purple" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-purple">
                      {portScans && portScans.length > 0 
                        ? Math.max(...portScans.map((s: PortScanDetection) => s.unique_ports))
                        : 0}
                    </div>
                    <div className="text-sm text-text-secondary">Max Ports by Single IP</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Bar Chart */}
            <Card>
              <CardHeader 
                title="Top Port Scanners" 
                subtitle="IPs scanning the most ports"
                icon={<Scan className="w-5 h-5 text-neon-orange" />}
              />
              <CardContent>
                {portScansLoading ? (
                  <div className="h-80 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={portScanChartData} layout="vertical" margin={{ left: 10 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" />
                        <YAxis 
                          dataKey="ip" 
                          type="category" 
                          stroke="#888888"
                          width={120}
                          tick={{ fontSize: 11, fill: '#888888' }}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                          }}
                          formatter={(value: number) => [value.toLocaleString(), 'Ports Scanned']}
                          labelFormatter={(label) => {
                            const item = portScanChartData.find(d => d.ip === label);
                            return item ? `${item.fullIp} (${item.country})` : label;
                          }}
                        />
                        <Bar dataKey="ports" radius={[0, 4, 4, 0]}>
                          {portScanChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Detailed Table */}
            <Card>
              <CardHeader 
                title="Port Scanner Details" 
                subtitle="Complete scanner information"
                icon={<AlertTriangle className="w-5 h-5 text-neon-orange" />}
              />
              <CardContent className="p-0">
                <div className="max-h-80 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-bg-card border-b border-bg-hover">
                      <tr>
                        <th className="text-left py-3 px-4 text-text-secondary font-medium">Source IP</th>
                        <th className="text-right py-3 px-4 text-text-secondary font-medium">Ports</th>
                        <th className="text-left py-3 px-4 text-text-secondary font-medium">Country</th>
                        <th className="text-left py-3 px-4 text-text-secondary font-medium">First Seen</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover">
                      {(portScans || []).slice(0, 15).map((scan: PortScanDetection, index: number) => (
                        <tr key={scan.src_ip} className="hover:bg-bg-hover/50">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <div 
                                className="w-2 h-2 rounded-full" 
                                style={{ backgroundColor: COLORS[index % COLORS.length] }}
                              />
                              <IPLink ip={scan.src_ip} />
                            </div>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <span className="font-mono text-neon-orange font-bold">
                              {scan.unique_ports.toLocaleString()}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-text-secondary">{scan.country || 'Unknown'}</td>
                          <td className="py-3 px-4 text-text-muted text-xs">
                            {new Date(scan.first_seen).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
    {
      id: 'repeat-offenders',
      label: 'Repeat Offenders',
      icon: <Users className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-neon-red/20">
                    <Users className="w-6 h-6 text-neon-red" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-red">
                      {repeatOffenders?.length || 0}
                    </div>
                    <div className="text-sm text-text-secondary">Repeat Offenders</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-neon-orange/20">
                    <ShieldAlert className="w-6 h-6 text-neon-orange" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-orange">
                      {repeatOffenders?.reduce((sum: number, o: RepeatOffender) => sum + o.total_blocks, 0)?.toLocaleString() || 0}
                    </div>
                    <div className="text-sm text-text-secondary">Total Blocks</div>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-neon-purple/20">
                    <TrendingUp className="w-6 h-6 text-neon-purple" />
                  </div>
                  <div>
                    <div className="text-3xl font-display font-bold text-neon-purple">
                      {repeatOffenders && repeatOffenders.length > 0 
                        ? Math.max(...repeatOffenders.map((o: RepeatOffender) => o.total_blocks)).toLocaleString()
                        : 0}
                    </div>
                    <div className="text-sm text-text-secondary">Max Blocks by Single IP</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Bar Chart */}
            <Card>
              <CardHeader 
                title="Top Offenders" 
                subtitle="Most frequently blocked IPs"
                icon={<Users className="w-5 h-5 text-neon-red" />}
              />
              <CardContent>
                {repeatOffendersLoading ? (
                  <div className="h-80 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={offenderChartData} layout="vertical" margin={{ left: 10 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" />
                        <YAxis 
                          dataKey="ip" 
                          type="category" 
                          stroke="#888888"
                          width={120}
                          tick={{ fontSize: 11, fill: '#888888' }}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                          }}
                          formatter={(value: number) => [value.toLocaleString(), 'Times Blocked']}
                          labelFormatter={(label) => {
                            const item = offenderChartData.find(d => d.ip === label);
                            return item ? `${item.fullIp} (${item.country})` : label;
                          }}
                        />
                        <Bar dataKey="blocks" radius={[0, 4, 4, 0]}>
                          {offenderChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Detailed Table */}
            <Card>
              <CardHeader 
                title="Offender Details" 
                subtitle="Complete offender information"
                icon={<AlertTriangle className="w-5 h-5 text-neon-red" />}
              />
              <CardContent className="p-0">
                <div className="max-h-80 overflow-y-auto">
                  <table className="w-full text-sm">
                    <thead className="sticky top-0 bg-bg-card border-b border-bg-hover">
                      <tr>
                        <th className="text-left py-3 px-4 text-text-secondary font-medium">Source IP</th>
                        <th className="text-right py-3 px-4 text-text-secondary font-medium">Blocks</th>
                        <th className="text-left py-3 px-4 text-text-secondary font-medium">Country</th>
                        <th className="text-left py-3 px-4 text-text-secondary font-medium">Ports</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover">
                      {(repeatOffenders || []).slice(0, 15).map((offender: RepeatOffender, index: number) => (
                        <tr key={offender.src_ip} className="hover:bg-bg-hover/50">
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <div 
                                className="w-2 h-2 rounded-full" 
                                style={{ backgroundColor: COLORS[index % COLORS.length] }}
                              />
                              <IPLink ip={offender.src_ip} />
                            </div>
                          </td>
                          <td className="py-3 px-4 text-right">
                            <span className="font-mono text-neon-red font-bold">
                              {offender.total_blocks.toLocaleString()}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-text-secondary">{offender.country || 'Unknown'}</td>
                          <td className="py-3 px-4 text-text-muted text-xs">
                            {offender.targeted_ports.slice(0, 5).join(', ')}
                            {offender.targeted_ports.length > 5 && '...'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
    {
      id: 'internal-hosts',
      label: 'Internal Hosts',
      icon: <Server className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <div className="flex gap-4">
            {INTERNAL_IPS.map((ip) => (
              <button
                key={ip}
                onClick={() => setSelectedInternalIP(ip)}
                className={`px-4 py-2 rounded-lg font-mono transition-colors ${
                  selectedInternalIP === ip
                    ? 'bg-neon-yellow/20 text-neon-yellow border border-neon-yellow/50'
                    : 'bg-bg-card text-text-secondary hover:text-text-primary'
                }`}
              >
                {ip}
              </button>
            ))}
          </div>

          {selectedInternalIP && (
            <Card>
              <CardHeader title={`Traffic to ${selectedInternalIP}`} />
              <CardContent>
                {internalHostLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : internalHostStats ? (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-bg-secondary rounded-lg p-4">
                          <div className="text-sm text-text-secondary">Total Events</div>
                          <div className="text-2xl font-display font-bold text-neon-yellow">
                            {(internalHostStats.total_events as number || 0).toLocaleString()}
                          </div>
                        </div>
                        <div className="bg-bg-secondary rounded-lg p-4">
                          <div className="text-sm text-text-secondary">Unique Sources</div>
                          <div className="text-2xl font-display font-bold text-neon-blue">
                            {(internalHostStats.unique_sources as number || 0).toLocaleString()}
                          </div>
                        </div>
                      </div>

                      <div className="bg-bg-secondary rounded-lg p-4">
                        <div className="text-sm text-text-secondary mb-3">Top Ports</div>
                        <div className="space-y-2">
                          {((internalHostStats.by_port as Array<{port: number; count: number}>) || []).slice(0, 5).map((item: {port: number; count: number}) => (
                            <div key={item.port} className="flex justify-between">
                              <span className="font-mono text-text-primary">{item.port}</span>
                              <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="bg-bg-secondary rounded-lg p-4">
                      <div className="text-sm text-text-secondary mb-3">Top Sources</div>
                      <div className="space-y-2">
                        {((internalHostStats.top_sources as Array<{ip: string; count: number; country?: string}>) || []).map((item: {ip: string; count: number; country?: string}) => (
                          <div key={item.ip} className="flex items-center justify-between p-2 bg-bg-card rounded-lg">
                            <div>
                              <IPLink ip={item.ip} />
                              {item.country && <span className="text-xs text-text-secondary ml-2">{item.country}</span>}
                            </div>
                            <span className="font-mono text-neon-yellow">{item.count.toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-text-secondary">Select an internal host to view statistics</div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      ),
    },
    {
      id: 'unexposed',
      label: 'Unexposed Ports',
      icon: <Eye className="w-4 h-4" />,
      content: <UnexposedPortsAnalysis timeRange={timeRange} />,
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-neon-yellow">Firewall (OPNsense)</h2>
          <p className="text-sm text-text-secondary mt-1">Network firewall traffic analysis</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />

      {/* Raw Log Modal */}
      {selectedEvent && (
        <RawLogModal
          log={selectedEvent}
          title="Firewall Event Details"
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
