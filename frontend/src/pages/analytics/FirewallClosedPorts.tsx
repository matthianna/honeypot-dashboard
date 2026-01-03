import { useCallback, useEffect } from 'react';
import { Ban, AlertTriangle, TrendingUp, Target } from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const EXPOSED_PORTS = [22, 23, 80, 443, 21, 2222, 3389, 5900, 445, 3306, 1433, 5060];

export default function FirewallClosedPorts() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: closedPorts, loading: closedLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallClosedPorts(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: scanners, loading: scannersLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallScanners(timeRange, 60, 20, 50),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (closedPorts) setLastUpdated(new Date());
  }, [closedPorts, setLastUpdated]);

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return ts;
    }
  };

  const portColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'port', header: 'Port', render: (item: any) => (
      <span className="font-mono text-neon-red">{item.port}</span>
    )},
    { key: 'count', header: 'Attack Attempts', render: (item: any) => item.count.toLocaleString() },
    { key: 'service', header: 'Likely Service', render: (item: any) => {
      const services: Record<number, string> = {
        8080: 'HTTP Proxy',
        8443: 'HTTPS Alt',
        8888: 'HTTP Alt',
        5555: 'Android ADB',
        6379: 'Redis',
        27017: 'MongoDB',
        9200: 'Elasticsearch',
        11211: 'Memcached',
        2375: 'Docker',
      };
      return services[item.port] || 'Unknown';
    }},
  ];

  const scannerColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'ip', header: 'IP Address', render: (item: any) => (
      <span className="font-mono text-neon-orange">{item.ip}</span>
    )},
    { key: 'unique_ports', header: 'Ports Scanned', render: (item: any) => (
      <span className="font-bold text-neon-red">{item.unique_ports}</span>
    )},
    { key: 'total_hits', header: 'Total Hits', render: (item: any) => item.total_hits.toLocaleString() },
    { key: 'country', header: 'Country' },
    { key: 'top_ports', header: 'Top Ports', render: (item: any) => (
      <span className="font-mono text-xs">{item.top_ports?.slice(0, 5).join(', ')}</span>
    )},
  ];

  if ((closedLoading || scannersLoading) && !closedPorts) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <Ban className="w-6 h-6 text-neon-red" />
            Closed Port Attacks
          </h2>
          <p className="text-sm text-text-muted mt-1">
            Attacks on ports NOT exposed by honeypots (ports other than {EXPOSED_PORTS.slice(0, 6).join(', ')}...)
          </p>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(closedPorts?.top_closed_ports || [], 'closed_port_attacks')}
        />
      </div>

      {/* KPIs */}
      <KPIGrid>
        <KPICard
          title="Total Closed Port Attacks"
          value={closedPorts?.total_attacks?.toLocaleString() || '0'}
          icon={<Ban className="w-5 h-5" />}
          color="red"
        />
        <KPICard
          title="Unique Attackers"
          value={closedPorts?.unique_attackers?.toLocaleString() || '0'}
          icon={<Target className="w-5 h-5" />}
          color="orange"
        />
        <KPICard
          title="Port Scanners Detected"
          value={scanners?.total_detected?.toString() || '0'}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="yellow"
        />
        <KPICard
          title="Unique Closed Ports Hit"
          value={closedPorts?.top_closed_ports?.length?.toString() || '0'}
          icon={<TrendingUp className="w-5 h-5" />}
          color="blue"
        />
      </KPIGrid>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Timeline */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4">Closed Port Attack Trend</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={closedPorts?.timeline || []}>
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={formatTime}
                  stroke="#4b5563"
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                />
                <YAxis stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }}
                  labelFormatter={(v) => new Date(v).toLocaleString()}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#ff3366"
                  fill="#ff336630"
                  name="Attacks"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Closed Ports */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4">Top Attacked Closed Ports</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={closedPorts?.top_closed_ports?.slice(0, 10) || []} layout="vertical">
                <XAxis type="number" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis dataKey="port" type="category" width={60} stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
                <Bar dataKey="count" fill="#ff3366" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Scan Detection Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover">
        <div className="p-4 border-b border-bg-hover flex items-center justify-between">
          <div>
            <h3 className="font-medium text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-neon-orange" />
              Port Scanner Detection
            </h3>
            <p className="text-xs text-text-muted mt-1">
              IPs hitting 20+ unique ports with 50+ blocked attempts
            </p>
          </div>
        </div>
        <DataTable
          columns={scannerColumns}
          data={scanners?.scanners || []}
          loading={scannersLoading}
          maxHeight="400px"
        />
      </div>

      {/* All Closed Ports */}
      <div className="bg-bg-card rounded-xl border border-bg-hover">
        <div className="p-4 border-b border-bg-hover">
          <h3 className="font-medium text-white">All Attacked Closed Ports</h3>
        </div>
        <DataTable
          columns={portColumns}
          data={closedPorts?.top_closed_ports || []}
          loading={closedLoading}
          maxHeight="400px"
        />
      </div>
    </div>
  );
}


