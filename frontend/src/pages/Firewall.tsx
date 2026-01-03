import { useCallback, useState } from 'react';
import { BarChart2, Clock, Map, ShieldAlert, Scan, Users, Server, List, Filter, Eye, Globe } from 'lucide-react';
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
import UnexposedPortsAnalysis from '../components/UnexposedPortsAnalysis';
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
