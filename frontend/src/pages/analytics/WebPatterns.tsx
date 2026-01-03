import { useCallback, useEffect } from 'react';
import { Globe, Link2, User, Code } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const COLORS = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366', '#ffcc00'];

export default function WebPatterns() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: paths, loading: pathsLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsWebPaths(timeRange, 30),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: userAgents, loading: uaLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsWebUseragents(timeRange, 20),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (paths) setLastUpdated(new Date());
  }, [paths, setLastUpdated]);

  const pathColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'path', header: 'URL Path', render: (item: any) => (
      <span className="font-mono text-sm text-neon-green">{item.path}</span>
    )},
    { key: 'count', header: 'Requests', render: (item: any) => item.count.toLocaleString() },
    { key: 'unique_ips', header: 'Unique IPs' },
    { key: 'methods', header: 'Methods', render: (item: any) => (
      <div className="flex gap-1">
        {Object.entries(item.methods || {}).map(([method, count]: [string, any]) => (
          <span 
            key={method}
            className={`px-1.5 py-0.5 rounded text-xs font-medium ${
              method === 'GET' ? 'bg-neon-green/20 text-neon-green' :
              method === 'POST' ? 'bg-neon-blue/20 text-neon-blue' :
              method === 'PUT' ? 'bg-neon-orange/20 text-neon-orange' :
              method === 'DELETE' ? 'bg-neon-red/20 text-neon-red' :
              'bg-bg-hover text-text-secondary'
            }`}
          >
            {method}: {count}
          </span>
        ))}
      </div>
    )},
  ];

  const uaColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'user_agent', header: 'User Agent', render: (item: any) => (
      <span className="text-sm text-text-secondary truncate max-w-md block">
        {item.user_agent}
      </span>
    )},
    { key: 'count', header: 'Requests', render: (item: any) => item.count.toLocaleString() },
    { key: 'unique_ips', header: 'Unique IPs' },
  ];

  // Categorize paths for insights
  const categorizedPaths = paths?.paths?.reduce((acc: any, p: any) => {
    const path = p.path.toLowerCase();
    if (path.includes('wp-') || path.includes('wordpress')) {
      acc.wordpress = (acc.wordpress || 0) + p.count;
    } else if (path.includes('phpmyadmin') || path.includes('mysql')) {
      acc.database = (acc.database || 0) + p.count;
    } else if (path.includes('.php') || path.includes('cgi')) {
      acc.scripts = (acc.scripts || 0) + p.count;
    } else if (path.includes('.env') || path.includes('config')) {
      acc.config = (acc.config || 0) + p.count;
    } else if (path.includes('admin') || path.includes('login')) {
      acc.admin = (acc.admin || 0) + p.count;
    } else {
      acc.other = (acc.other || 0) + p.count;
    }
    return acc;
  }, {}) || {};

  const categoryData = Object.entries(categorizedPaths).map(([name, count]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value: count as number,
  }));

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="Total Paths"
          value={paths?.paths?.length || 0}
          icon={<Link2 className="w-5 h-5" />}
          color="green"
          loading={pathsLoading}
        />
        <KPICard
          title="Total Requests"
          value={paths?.paths?.reduce((a: number, p: any) => a + p.count, 0) || 0}
          icon={<Globe className="w-5 h-5" />}
          color="blue"
          loading={pathsLoading}
        />
        <KPICard
          title="User Agents"
          value={userAgents?.user_agents?.length || 0}
          icon={<User className="w-5 h-5" />}
          color="orange"
          loading={uaLoading}
        />
        <KPICard
          title="Script Probes"
          value={categorizedPaths.scripts || 0}
          icon={<Code className="w-5 h-5" />}
          color="red"
          loading={pathsLoading}
        />
      </KPIGrid>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Paths Bar */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Link2 className="w-5 h-5 text-neon-green" />
            Top URL Paths
          </h3>
          {pathsLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={paths?.paths?.slice(0, 8) || []} layout="vertical">
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="path"
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 10 }}
                    width={150}
                    tickFormatter={(v) => v.length > 25 ? v.slice(0, 25) + '...' : v}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" fill="#39ff14" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Category Distribution */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Code className="w-5 h-5 text-neon-blue" />
            Attack Categories
          </h3>
          {pathsLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={categoryData}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    dataKey="value"
                    nameKey="name"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {categoryData.map((_, i) => (
                      <Cell key={i} fill={COLORS[i % COLORS.length]} />
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
            </div>
          )}
        </div>
      </div>

      {/* Full Path Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-bold text-white">All URL Paths</h3>
          <ExportToolbar
            onExportCSV={() => exportToCSV(paths?.paths || [], 'web_paths')}
          />
        </div>
        <DataTable
          columns={pathColumns}
          data={paths?.paths || []}
          loading={pathsLoading}
          maxHeight="400px"
        />
      </div>

      {/* User Agents Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-bold text-white flex items-center gap-2">
            <User className="w-5 h-5 text-neon-orange" />
            User Agents
          </h3>
          <ExportToolbar
            onExportCSV={() => exportToCSV(userAgents?.user_agents || [], 'user_agents')}
          />
        </div>
        <DataTable
          columns={uaColumns}
          data={userAgents?.user_agents || []}
          loading={uaLoading}
          maxHeight="350px"
        />
      </div>
    </div>
  );
}

