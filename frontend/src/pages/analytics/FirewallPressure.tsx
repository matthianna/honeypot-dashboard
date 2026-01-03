import { useCallback, useEffect, useState } from 'react';
import { Flame, Shield, Ban, Globe, Activity } from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
  Legend,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV, exportToPNG } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const PROTOCOL_COLORS: Record<string, string> = {
  tcp: '#39ff14',
  udp: '#00d4ff',
  icmp: '#ff6600',
};

export default function FirewallPressure() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [direction, setDirection] = useState<'in' | 'out' | 'all'>('in');

  const { data: overview, loading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallOverview(timeRange, direction),
    [timeRange, direction]),
    [timeRange, direction],
    30000
  );

  useEffect(() => {
    if (overview) setLastUpdated(new Date());
  }, [overview, setLastUpdated]);

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
      <span className="font-mono text-neon-green">{item.port}</span>
    )},
    { key: 'count', header: 'Blocked Attempts', render: (item: any) => item.count.toLocaleString() },
  ];

  const countryColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'country', header: 'Country' },
    { key: 'count', header: 'Blocked', render: (item: any) => item.count.toLocaleString() },
  ];

  if (loading && !overview) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  const kpis = overview?.kpis || {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <Flame className="w-6 h-6 text-neon-orange" />
            Firewall Pressure Overview
          </h2>
          <div className="flex bg-bg-card rounded-lg border border-bg-hover">
            {(['in', 'out', 'all'] as const).map((dir) => (
              <button
                key={dir}
                onClick={() => setDirection(dir)}
                className={`px-3 py-1.5 text-sm font-medium transition-colors ${
                  direction === dir
                    ? 'bg-neon-green/20 text-neon-green'
                    : 'text-text-muted hover:text-text-primary'
                }`}
              >
                {dir.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(overview?.top_blocked_ports || [], 'firewall_ports')}
          onExportPNG={() => exportToPNG('firewall-chart', 'firewall_timeline')}
        />
      </div>

      {/* KPIs */}
      <KPIGrid>
        <KPICard
          title="Total Attempts"
          value={kpis.total_attempts?.toLocaleString() || '0'}
          icon={<Activity className="w-5 h-5" />}
          color="blue"
        />
        <KPICard
          title="Blocked"
          value={kpis.blocked?.toLocaleString() || '0'}
          icon={<Ban className="w-5 h-5" />}
          color="red"
        />
        <KPICard
          title="Allowed"
          value={kpis.allowed?.toLocaleString() || '0'}
          icon={<Shield className="w-5 h-5" />}
          color="green"
        />
        <KPICard
          title="Block Rate"
          value={`${kpis.block_rate || 0}%`}
          icon={<Flame className="w-5 h-5" />}
          color="orange"
        />
      </KPIGrid>

      {/* Timeline Chart */}
      <div id="firewall-chart" className="bg-bg-card rounded-xl border border-bg-hover p-6">
        <h3 className="font-medium text-white mb-4">Blocked vs Allowed Traffic</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={overview?.timeline || []}>
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
                dataKey="blocked"
                stackId="1"
                stroke="#ff3366"
                fill="#ff336630"
                name="Blocked"
              />
              <Area
                type="monotone"
                dataKey="allowed"
                stackId="1"
                stroke="#39ff14"
                fill="#39ff1430"
                name="Allowed"
              />
              <Legend />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Blocked Ports */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4">Top Blocked Ports</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={overview?.top_blocked_ports?.slice(0, 8) || []} layout="vertical">
                <XAxis type="number" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis dataKey="port" type="category" width={50} stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
                <Bar dataKey="count" fill="#ff3366" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocols */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4">Protocol Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={overview?.protocols || []}
                  dataKey="count"
                  nameKey="protocol"
                  cx="50%"
                  cy="50%"
                  outerRadius={60}
                  label={({ protocol }) => protocol?.toUpperCase()}
                >
                  {(overview?.protocols || []).map((entry: any, index: number) => (
                    <Cell key={index} fill={PROTOCOL_COLORS[entry.protocol] || '#888'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Countries */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4 flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Top Blocked Countries
          </h3>
          <DataTable
            columns={countryColumns}
            data={overview?.top_countries?.slice(0, 8) || []}
            loading={loading}
            maxHeight="180px"
          />
        </div>
      </div>

      {/* Detailed Ports Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover">
        <div className="p-4 border-b border-bg-hover">
          <h3 className="font-medium text-white">All Blocked Destination Ports</h3>
        </div>
        <DataTable
          columns={portColumns}
          data={overview?.top_blocked_ports || []}
          loading={loading}
          maxHeight="300px"
        />
      </div>
    </div>
  );
}


