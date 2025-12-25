import { useCallback, useState } from 'react';
import { BarChart2, Clock, Map, ShieldAlert, Scan, Users, Server, List, Filter, Eye, Globe, TrendingUp, FileText } from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import TimeRangeSelector from '../components/TimeRangeSelector';
import Tabs from '../components/Tabs';
import DataTable from '../components/DataTable';
import IPLink from '../components/IPLink';
import LoadingSpinner from '../components/LoadingSpinner';
import RawLogModal from '../components/RawLogModal';
import FirewallAttackMap from '../components/FirewallAttackMap';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { FirewallBlockedTraffic, PortScanDetection, RepeatOffender, GeoPoint } from '../types';

const COLORS = ['#ffff00', '#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366'];
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

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallGeo(timeRange), [timeRange]),
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

  const { data: ruleStats, loading: ruleStatsLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallRuleStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: actionTimeline, loading: actionTimelineLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallActionTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: directionStats, loading: directionStatsLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallDirectionStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: tcpFlags, loading: tcpFlagsLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallTcpFlags(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: ttlAnalysis, loading: ttlAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallTtlAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: packetSizes, loading: packetSizesLoading } = useApiWithRefresh(
    useCallback(() => api.getFirewallPacketSizes(timeRange), [timeRange]),
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

  const portScanColumns = [
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: PortScanDetection) => <IPLink ip={item.src_ip} />,
    },
    {
      key: 'unique_ports',
      header: 'Ports Scanned',
      render: (item: PortScanDetection) => (
        <span className="font-mono text-neon-orange">{item.unique_ports}</span>
      ),
    },
    {
      key: 'first_seen',
      header: 'First Seen',
      render: (item: PortScanDetection) => (
        <span className="text-text-secondary text-sm">{new Date(item.first_seen).toLocaleString()}</span>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (item: PortScanDetection) => (
        <span className="text-text-secondary">{item.country || 'Unknown'}</span>
      ),
    },
  ];

  const repeatOffenderColumns = [
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (item: RepeatOffender) => <IPLink ip={item.src_ip} />,
    },
    {
      key: 'total_blocks',
      header: 'Total Blocks',
      render: (item: RepeatOffender) => (
        <span className="font-mono text-neon-red">{item.total_blocks.toLocaleString()}</span>
      ),
    },
    {
      key: 'targeted_ports',
      header: 'Targeted Ports',
      render: (item: RepeatOffender) => (
        <span className="text-text-secondary text-sm">{item.targeted_ports.slice(0, 5).join(', ')}</span>
      ),
    },
    {
      key: 'country',
      header: 'Country',
      render: (item: RepeatOffender) => (
        <span className="text-text-secondary">{item.country || 'Unknown'}</span>
      ),
    },
  ];

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
          <span className={`px-2 py-1 rounded text-xs font-mono ${actionColors[action] || 'text-text-secondary bg-bg-hover'}`}>
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
        return source ? <IPLink ip={source.ip} /> : <span className="text-text-secondary">-</span>;
      },
    },
    {
      key: 'destination',
      header: 'Destination',
      render: (item: Record<string, unknown>) => {
        const dest = item.destination as { ip: string; port: number } | undefined;
        return dest ? (
          <span className="font-mono text-sm">
            <span className="text-text-primary">{dest.ip}</span>
            <span className="text-text-secondary">:{dest.port}</span>
          </span>
        ) : <span className="text-text-secondary">-</span>;
      },
    },
    {
      key: 'transport',
      header: 'Protocol',
      render: (item: Record<string, unknown>) => (
        <span className="text-text-secondary text-sm uppercase">{item.transport as string || '-'}</span>
      ),
    },
    {
      key: 'interface',
      header: 'Interface',
      render: (item: Record<string, unknown>) => (
        <span className="font-mono text-xs text-text-secondary">{item.interface as string || '-'}</span>
      ),
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
                data={events?.events || []} 
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
        <Card>
          <CardHeader title="Detected Port Scans" subtitle="IPs scanning multiple ports" />
          <CardContent className="p-0">
            <DataTable columns={portScanColumns} data={portScans || []} loading={portScansLoading} emptyMessage="No port scans detected" />
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'repeat-offenders',
      label: 'Repeat Offenders',
      icon: <Users className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Repeat Offenders" subtitle="IPs blocked multiple times" />
          <CardContent className="p-0">
            <DataTable columns={repeatOffenderColumns} data={repeatOffenders || []} loading={repeatOffendersLoading} emptyMessage="No repeat offenders" />
          </CardContent>
        </Card>
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
      id: 'map',
      label: 'Geographic',
      icon: <Map className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Traffic Origins" />
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
                      <span className="font-mono text-neon-yellow">{item.count.toLocaleString()}</span>
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
          {/* Action Timeline */}
          <Card>
            <CardHeader 
              title="Block vs Pass Actions Over Time" 
              subtitle={`Total: Block ${actionTimeline?.totals?.block?.toLocaleString() || 0} | Pass ${actionTimeline?.totals?.pass?.toLocaleString() || 0}`}
              icon={<ShieldAlert className="w-5 h-5" />} 
            />
            <CardContent>
              {actionTimelineLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={actionTimeline?.timeline || []}>
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
                      <Area type="monotone" dataKey="block" name="Blocked" stroke="#ff3366" fill="#ff3366" fillOpacity={0.5} stackId="1" />
                      <Area type="monotone" dataKey="pass" name="Passed" stroke="#39ff14" fill="#39ff14" fillOpacity={0.5} stackId="1" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Direction Stats */}
            <Card>
              <CardHeader title="Traffic Direction Breakdown" subtitle="Inbound vs Outbound traffic" icon={<Filter className="w-5 h-5" />} />
              <CardContent>
                {directionStatsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-4">
                    {directionStats?.directions?.map((d) => (
                      <div key={d.direction} className="bg-bg-secondary rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-text-primary capitalize">{d.direction}</span>
                          <span className="font-mono text-neon-yellow">{d.count.toLocaleString()}</span>
                        </div>
                        <div className="grid grid-cols-3 gap-2 text-sm">
                          <div className="text-center">
                            <div className="text-neon-red font-bold">{d.block_count.toLocaleString()}</div>
                            <div className="text-text-muted text-xs">Blocked</div>
                          </div>
                          <div className="text-center">
                            <div className="text-neon-green font-bold">{d.pass_count.toLocaleString()}</div>
                            <div className="text-text-muted text-xs">Passed</div>
                          </div>
                          <div className="text-center">
                            <div className="text-neon-blue font-bold">{d.unique_sources.toLocaleString()}</div>
                            <div className="text-text-muted text-xs">Sources</div>
                          </div>
                        </div>
                        <div className="flex gap-1 mt-2">
                          {d.top_ports.slice(0, 5).map((port) => (
                            <span key={port} className="px-2 py-0.5 bg-bg-primary rounded text-xs font-mono">{port}</span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Rule Stats */}
            <Card>
              <CardHeader 
                title="Firewall Rule Triggers" 
                subtitle={`${ruleStats?.total_rules || 0} unique rules triggered`}
                icon={<FileText className="w-5 h-5" />} 
              />
              <CardContent>
                {ruleStatsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={ruleStats?.rules?.slice(0, 8) || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                        <YAxis 
                          type="category" 
                          dataKey="rule" 
                          stroke="#888888" 
                          tick={{ fill: '#888888', fontSize: 9 }} 
                          width={80}
                          tickFormatter={(v) => v.length > 10 ? `${v.slice(0, 10)}...` : v}
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
                        <Bar dataKey="block_count" name="Block" fill="#ff3366" stackId="a" />
                        <Bar dataKey="pass_count" name="Pass" fill="#39ff14" stackId="a" />
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
      id: 'packet-analysis',
      label: 'Packet Analysis',
      icon: <Scan className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* TCP Flags and Scan Detection */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader 
                title="Scan Type Detection" 
                subtitle={`${tcpFlags?.total_tcp_packets?.toLocaleString() || 0} TCP packets analyzed`}
                icon={<Scan className="w-5 h-5" />}
              />
              <CardContent>
                {tcpFlagsLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={tcpFlags?.scan_types || []}
                          cx="50%"
                          cy="50%"
                          innerRadius={40}
                          outerRadius={70}
                          paddingAngle={2}
                          dataKey="count"
                          nameKey="scan_type"
                        >
                          {tcpFlags?.scan_types?.map((_, index) => (
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
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader 
                title="IP Flags Distribution" 
                subtitle="DF (Don't Fragment) vs none"
              />
              <CardContent>
                {tcpFlagsLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-3">
                    {tcpFlags?.flags?.slice(0, 6).map((item, index) => (
                      <div key={item.flag || 'empty'} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                        <div className="flex items-center">
                          <div 
                            className="w-3 h-3 rounded-full mr-3"
                            style={{ backgroundColor: COLORS[index % COLORS.length] }}
                          />
                          <span className="font-mono text-text-primary">{item.flag || '(none)'}</span>
                        </div>
                        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                      </div>
                    ))}
                    {(!tcpFlags?.flags || tcpFlags.flags.length === 0) && (
                      <div className="text-center py-4 text-text-secondary text-sm">No flag data available</div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* OS Fingerprinting via TTL */}
          <Card>
            <CardHeader 
              title="OS Fingerprinting (TTL Analysis)" 
              subtitle={`${ttlAnalysis?.total_packets?.toLocaleString() || 0} packets with TTL info`}
              icon={<Server className="w-5 h-5" />}
            />
            <CardContent>
              {ttlAnalysisLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* OS Distribution */}
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">Estimated Source OS</h4>
                    <div className="h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={ttlAnalysis?.os_fingerprints || []}
                            cx="50%"
                            cy="50%"
                            innerRadius={40}
                            outerRadius={70}
                            paddingAngle={2}
                            dataKey="count"
                            nameKey="os"
                          >
                            {ttlAnalysis?.os_fingerprints?.map((_, index) => (
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
                  </div>

                  {/* TTL Distribution */}
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">TTL Values Observed</h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {ttlAnalysis?.ttl_distribution?.slice(0, 10).map((item) => (
                        <div key={item.ttl} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <div className="flex items-center gap-3">
                            <span className="font-mono text-neon-blue">TTL {item.ttl}</span>
                            <span className="text-xs text-text-muted">→ ~{item.estimated_hops} hops</span>
                            <span className="px-2 py-0.5 text-xs rounded bg-neon-purple/20 text-neon-purple">{item.os_guess}</span>
                          </div>
                          <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Packet Size Distribution */}
          <Card>
            <CardHeader 
              title="Packet Size Distribution" 
              subtitle={`Avg: ${packetSizes?.stats?.avg || 0} bytes | Min: ${packetSizes?.stats?.min || 0} | Max: ${packetSizes?.stats?.max || 0}`}
            />
            <CardContent>
              {packetSizesLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Histogram */}
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">Size Histogram</h4>
                    <div className="h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={packetSizes?.histogram?.slice(0, 12) || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis 
                            dataKey="range" 
                            stroke="#888888" 
                            tick={{ fill: '#888888', fontSize: 9 }}
                            angle={-45}
                            textAnchor="end"
                            height={50}
                          />
                          <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#1a1a25',
                              border: '1px solid #252532',
                              borderRadius: '8px',
                              color: '#e0e0e0',
                            }}
                          />
                          <Bar dataKey="count" fill="#ffff00" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Common Sizes */}
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">Most Common Sizes</h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {packetSizes?.common_sizes?.slice(0, 10).map((item) => (
                        <div key={item.size} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-neon-yellow">{item.size} bytes</span>
                            {item.meaning && (
                              <span className="text-xs text-text-muted">({item.meaning})</span>
                            )}
                          </div>
                          <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
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
      id: 'attack-map',
      label: 'Attack Map',
      icon: <Globe className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <Card>
            <CardHeader 
              title="Live Firewall Attack Map" 
              subtitle="Real-time visualization of blocked traffic"
              icon={<Globe className="w-5 h-5" />} 
            />
            <CardContent className="p-0">
              <FirewallAttackMap timeRange={timeRange} />
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
