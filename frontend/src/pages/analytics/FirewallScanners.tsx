import { useCallback, useEffect, useState } from 'react';
import { Search, Target, Clock, Activity } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function FirewallScanners() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [minPorts, setMinPorts] = useState(20);
  const [minHits, setMinHits] = useState(50);

  const { data: scanners, loading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallScanners(timeRange, 60, minPorts, minHits),
    [timeRange, minPorts, minHits]),
    [timeRange, minPorts, minHits],
    60000
  );

  useEffect(() => {
    if (scanners) setLastUpdated(new Date());
  }, [scanners, setLastUpdated]);

  const scannerColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'ip', header: 'IP Address', render: (item: any) => <IPLink ip={item.ip} /> },
    { key: 'unique_ports', header: 'Ports Scanned', render: (item: any) => (
      <span className="font-bold text-neon-red">{item.unique_ports}</span>
    )},
    { key: 'total_hits', header: 'Total Hits', render: (item: any) => item.total_hits.toLocaleString() },
    { key: 'country', header: 'Country' },
    { key: 'first_seen', header: 'First Seen', render: (item: any) => {
      try {
        return new Date(item.first_seen).toLocaleString();
      } catch {
        return item.first_seen;
      }
    }},
    { key: 'last_seen', header: 'Last Seen', render: (item: any) => {
      try {
        return new Date(item.last_seen).toLocaleString();
      } catch {
        return item.last_seen;
      }
    }},
    { key: 'top_ports', header: 'Sample Ports', render: (item: any) => (
      <span className="font-mono text-xs text-text-muted">{item.top_ports?.slice(0, 5).join(', ')}</span>
    )},
  ];

  if (loading && !scanners) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  // Aggregate port scan targets
  const portCounts: Record<number, number> = {};
  scanners?.scanners?.forEach((s: any) => {
    s.top_ports?.forEach((port: number) => {
      portCounts[port] = (portCounts[port] || 0) + 1;
    });
  });
  const topScannedPorts = Object.entries(portCounts)
    .map(([port, count]) => ({ port: Number(port), scanners: count }))
    .sort((a, b) => b.scanners - a.scanners)
    .slice(0, 10);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <Search className="w-6 h-6 text-neon-orange" />
            Port Scan Detection
          </h2>
          <p className="text-sm text-text-muted mt-1">
            Heuristic-based detection: IPs hitting many distinct blocked ports
          </p>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(scanners?.scanners || [], 'port_scanners')}
        />
      </div>

      {/* Threshold Controls */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <h3 className="font-medium text-white mb-3">Detection Thresholds</h3>
        <div className="flex flex-wrap gap-6">
          <div>
            <label className="block text-sm text-text-muted mb-1">Min Unique Ports</label>
            <input
              type="number"
              value={minPorts}
              onChange={(e) => setMinPorts(Number(e.target.value))}
              className="w-24 px-3 py-2 bg-bg-secondary border border-bg-hover rounded-lg text-text-primary focus:border-neon-green focus:outline-none"
              min={5}
              max={100}
            />
          </div>
          <div>
            <label className="block text-sm text-text-muted mb-1">Min Blocked Hits</label>
            <input
              type="number"
              value={minHits}
              onChange={(e) => setMinHits(Number(e.target.value))}
              className="w-24 px-3 py-2 bg-bg-secondary border border-bg-hover rounded-lg text-text-primary focus:border-neon-green focus:outline-none"
              min={10}
              max={1000}
            />
          </div>
        </div>
        <p className="text-xs text-text-muted mt-2">
          An IP is flagged as scanner if: unique_dst_ports ≥ {minPorts} AND blocked_attempts ≥ {minHits}
        </p>
      </div>

      {/* KPIs */}
      <KPIGrid>
        <KPICard
          title="Scanners Detected"
          value={scanners?.total_detected?.toString() || '0'}
          icon={<Target className="w-5 h-5" />}
          color="red"
        />
        <KPICard
          title="Avg Ports per Scanner"
          value={scanners?.scanners?.length > 0 
            ? Math.round(scanners.scanners.reduce((a: number, s: any) => a + s.unique_ports, 0) / scanners.scanners.length).toString()
            : '0'}
          icon={<Activity className="w-5 h-5" />}
          color="orange"
        />
        <KPICard
          title="Total Scan Attempts"
          value={scanners?.scanners?.reduce((a: number, s: any) => a + s.total_hits, 0)?.toLocaleString() || '0'}
          icon={<Search className="w-5 h-5" />}
          color="yellow"
        />
        <KPICard
          title="Countries Involved"
          value={new Set(scanners?.scanners?.map((s: any) => s.country)).size.toString() || '0'}
          icon={<Clock className="w-5 h-5" />}
          color="blue"
        />
      </KPIGrid>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scanners Table */}
        <div className="lg:col-span-2">
          <div className="bg-bg-card rounded-xl border border-bg-hover">
            <div className="p-4 border-b border-bg-hover">
              <h3 className="font-medium text-white">Detected Port Scanners</h3>
            </div>
            <DataTable
              columns={scannerColumns}
              data={scanners?.scanners || []}
              loading={loading}
              maxHeight="500px"
            />
          </div>
        </div>

        {/* Top Scanned Ports */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4">Most Targeted Ports by Scanners</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topScannedPorts} layout="vertical">
                <XAxis type="number" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis dataKey="port" type="category" width={50} stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
                <Bar dataKey="scanners" fill="#ff6600" name="Scanners" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

