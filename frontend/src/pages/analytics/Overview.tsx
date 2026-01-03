import { useCallback, useEffect } from 'react';
import {
  Activity,
  Users,
  Shield,
  Globe,
  Terminal,
  Key,
  Zap,
} from 'lucide-react';
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
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV, exportToPNG } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
  firewall: '#ffff00',
};

export default function Overview() {
  const { timeRange, filters, setLastUpdated } = useAnalytics();

  const { data: overview, loading: overviewLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsOverview(timeRange, filters.honeypot),
    [timeRange, filters.honeypot]),
    [timeRange, filters.honeypot],
    30000
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsOverviewTimeline(timeRange, filters.honeypot),
    [timeRange, filters.honeypot]),
    [timeRange, filters.honeypot],
    30000
  );

  const { data: attackers, loading: attackersLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsOverviewTopAttackers(timeRange, 10, filters.honeypot),
    [timeRange, filters.honeypot]),
    [timeRange, filters.honeypot],
    30000
  );

  const { data: countries, loading: countriesLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsOverviewCountries(timeRange, 10),
    [timeRange]),
    [timeRange],
    60000
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

  const attackerColumns = [
    { key: 'ip', header: 'IP Address', render: (item: any) => <IPLink ip={item.ip} /> },
    { key: 'events', header: 'Events', render: (item: any) => item.events.toLocaleString() },
    { key: 'honeypots', header: 'Honeypots', render: (item: any) => item.honeypots?.length || 0 },
    { key: 'country', header: 'Country' },
    { key: 'first_seen', header: 'First Seen', render: (item: any) => 
      item.first_seen ? new Date(item.first_seen).toLocaleString() : '-' 
    },
  ];

  const honeypotData = overview?.honeypot_breakdown 
    ? Object.entries(overview.honeypot_breakdown).map(([name, data]: [string, any]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        events: data.events || 0,
        color: HONEYPOT_COLORS[name] || '#888',
      }))
    : [];

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <KPIGrid columns={4}>
        <KPICard
          title="Total Events"
          value={overview?.kpis?.total_events || 0}
          icon={<Activity className="w-5 h-5" />}
          color="green"
          loading={overviewLoading}
        />
        <KPICard
          title="Unique Attackers"
          value={overview?.kpis?.unique_ips || 0}
          icon={<Users className="w-5 h-5" />}
          color="blue"
          loading={overviewLoading}
        />
        <KPICard
          title="Auth Attempts"
          value={overview?.kpis?.auth_attempts || 0}
          icon={<Key className="w-5 h-5" />}
          color="orange"
          loading={overviewLoading}
        />
        <KPICard
          title="Sessions"
          value={overview?.kpis?.total_sessions || 0}
          icon={<Terminal className="w-5 h-5" />}
          color="purple"
          loading={overviewLoading}
        />
      </KPIGrid>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Chart */}
        <div className="lg:col-span-2 bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-neon-green" />
              Events Over Time
            </h3>
            <ExportToolbar
              onExportPNG={() => exportToPNG('timeline-chart', 'events_timeline')}
            />
          </div>
          <div id="timeline-chart" className="h-64">
            {timelineLoading ? (
              <div className="h-full flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline?.timeline || []}>
                  <defs>
                    <linearGradient id="overviewGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#39ff14" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#39ff14" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatTime}
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 11 }}
                    axisLine={false}
                  />
                  <YAxis stroke="#555" tick={{ fill: '#888', fontSize: 11 }} axisLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                    labelFormatter={formatTime}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#39ff14"
                    fill="url(#overviewGradient)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Honeypot Distribution */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-neon-blue" />
              By Honeypot
            </h3>
          </div>
          <div className="h-64">
            {overviewLoading ? (
              <div className="h-full flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={honeypotData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    dataKey="events"
                    nameKey="name"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {honeypotData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attackers Table */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-neon-red" />
              Top Attackers
            </h3>
            <ExportToolbar
              onExportCSV={() => exportToCSV(attackers?.attackers || [], 'top_attackers')}
            />
          </div>
          <DataTable
            columns={attackerColumns}
            data={attackers?.attackers || []}
            loading={attackersLoading}
            maxHeight="300px"
          />
        </div>

        {/* Protocol & Country Charts */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-display font-bold text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-neon-orange" />
              Top Countries
            </h3>
          </div>
          <div className="h-64">
            {countriesLoading ? (
              <div className="h-full flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={countries?.countries?.slice(0, 8) || []} layout="vertical">
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="country"
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 11 }}
                    width={100}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="total" fill="#00d4ff" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

