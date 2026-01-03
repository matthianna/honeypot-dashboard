import { useCallback, useEffect, useState } from 'react';
import { Shield, Target, AlertTriangle } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const TACTIC_COLORS: Record<string, string> = {
  'Initial Access': '#ff3366',
  'Execution': '#39ff14',
  'Persistence': '#00d4ff',
  'Privilege Escalation': '#ff6600',
  'Defense Evasion': '#bf00ff',
  'Credential Access': '#ffcc00',
  'Discovery': '#00ff88',
  'Lateral Movement': '#ff00ff',
  'Collection': '#00ffff',
  'Command and Control': '#ff8800',
  'Exfiltration': '#ff0066',
  'Impact': '#ff0000',
};

export default function Mitre() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [selectedVariant, setSelectedVariant] = useState<string | null>(null);

  const { data: summary, loading: summaryLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsMitreSummary(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: techniques, loading: techLoading } = useApiWithRefresh(
    useCallback(() => 
      api.getAnalyticsMitreTechniques(timeRange, selectedVariant || undefined),
    [timeRange, selectedVariant]),
    [timeRange, selectedVariant],
    60000
  );

  useEffect(() => {
    if (summary) setLastUpdated(new Date());
  }, [summary, setLastUpdated]);

  const techniqueColumns = [
    { key: 'id', header: 'ID', render: (item: any) => (
      <span className="font-mono text-neon-blue">{item.id}</span>
    )},
    { key: 'name', header: 'Technique' },
    { key: 'tactic', header: 'Tactic', render: (item: any) => (
      <span 
        className="px-2 py-0.5 rounded text-xs"
        style={{ 
          backgroundColor: `${TACTIC_COLORS[item.tactic] || '#888'}20`,
          color: TACTIC_COLORS[item.tactic] || '#888'
        }}
      >
        {item.tactic}
      </span>
    )},
    { key: 'count', header: 'Events', render: (item: any) => item.count.toLocaleString() },
    { key: 'sample_commands', header: 'Evidence', render: (item: any) => (
      <div className="max-w-xs">
        {item.sample_commands?.slice(0, 2).map((cmd: string, i: number) => (
          <div key={i} className="font-mono text-xs text-text-muted truncate">
            $ {cmd}
          </div>
        ))}
      </div>
    )},
  ];

  return (
    <div className="space-y-6">
      {/* KPIs */}
      <KPIGrid columns={4}>
        <KPICard
          title="Techniques Detected"
          value={summary?.summary?.detected || 0}
          subtitle={`of ${summary?.summary?.total || 0} total`}
          icon={<Target className="w-5 h-5" />}
          color="green"
          loading={summaryLoading}
        />
        <KPICard
          title="Total Events"
          value={summary?.summary?.events || 0}
          icon={<AlertTriangle className="w-5 h-5" />}
          color="orange"
          loading={summaryLoading}
        />
        <KPICard
          title="Active Tactics"
          value={summary?.tactics?.filter((t: any) => t.total > 0).length || 0}
          icon={<Shield className="w-5 h-5" />}
          color="blue"
          loading={summaryLoading}
        />
        <KPICard
          title="Top Technique"
          value={summary?.techniques?.[0]?.name || '-'}
          subtitle={`${summary?.techniques?.[0]?.count?.toLocaleString() || 0} events`}
          icon={<Target className="w-5 h-5" />}
          color="red"
          loading={summaryLoading}
        />
      </KPIGrid>

      {/* Variant Filter */}
      <div className="flex items-center gap-4">
        <span className="text-sm text-text-muted">Filter by variant:</span>
        {['plain', 'openai', 'ollama'].map((v) => (
          <button
            key={v}
            onClick={() => setSelectedVariant(selectedVariant === v ? null : v)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
              selectedVariant === v
                ? 'bg-neon-green/20 text-neon-green'
                : 'bg-bg-secondary text-text-secondary hover:text-text-primary'
            }`}
          >
            {v.charAt(0).toUpperCase() + v.slice(1)}
          </button>
        ))}
        {selectedVariant && (
          <button
            onClick={() => setSelectedVariant(null)}
            className="text-sm text-neon-red hover:underline"
          >
            Clear
          </button>
        )}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Technique Bar Chart */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-neon-green" />
            Top Techniques
          </h3>
          {summaryLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary?.techniques?.slice(0, 8) || []} layout="vertical">
                  <XAxis type="number" stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#555"
                    tick={{ fill: '#888', fontSize: 10 }}
                    width={120}
                    tickFormatter={(v) => v.length > 15 ? v.slice(0, 15) + '...' : v}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {(summary?.techniques?.slice(0, 8) || []).map((tech: any, i: number) => (
                      <Cell key={i} fill={TACTIC_COLORS[tech.tactic] || '#39ff14'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Tactic Distribution */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
          <h3 className="font-display font-bold text-white mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-neon-blue" />
            Tactics Distribution
          </h3>
          {summaryLoading ? (
            <div className="h-64 flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={summary?.tactics?.filter((t: any) => t.total > 0) || []}>
                  <XAxis 
                    dataKey="tactic" 
                    stroke="#555" 
                    tick={{ fill: '#888', fontSize: 9 }}
                    height={80}
                    interval={0}
                    tickFormatter={(v) => v.length > 12 ? v.slice(0, 12) + '...' : v}
                  />
                  <YAxis stroke="#555" tick={{ fill: '#888', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(26, 26, 37, 0.95)',
                      border: '1px solid rgba(255,255,255,0.1)',
                      borderRadius: '8px',
                    }}
                  />
                  <Bar dataKey="total" radius={[4, 4, 0, 0]}>
                    {(summary?.tactics || []).map((t: any, i: number) => (
                      <Cell key={i} fill={TACTIC_COLORS[t.tactic] || '#39ff14'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Techniques Table with Evidence */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display font-bold text-white flex items-center gap-2">
            <Target className="w-5 h-5 text-neon-orange" />
            Technique Details with Evidence
          </h3>
          <ExportToolbar
            onExportCSV={() => exportToCSV(techniques?.techniques || [], 'mitre_techniques')}
          />
        </div>
        <DataTable
          columns={techniqueColumns}
          data={techniques?.techniques || []}
          loading={techLoading}
          maxHeight="400px"
        />
      </div>

      {/* Legend */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
        <h3 className="font-display font-bold text-white mb-4">Tactic Legend</h3>
        <div className="flex flex-wrap gap-3">
          {Object.entries(TACTIC_COLORS).map(([tactic, color]) => (
            <div key={tactic} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded" style={{ backgroundColor: color }} />
              <span className="text-sm text-text-secondary">{tactic}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

