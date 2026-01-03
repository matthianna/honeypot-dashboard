import { useCallback, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function FirewallRules() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: rules, loading: rulesLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallRules(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: unexpected, loading: unexpectedLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsFirewallUnexpectedPass(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (rules) setLastUpdated(new Date());
  }, [rules, setLastUpdated]);

  const ruleColumns = [
    { key: 'rule_id', header: 'Rule ID', render: (item: any) => (
      <span className="font-mono text-neon-blue">#{item.rule_id}</span>
    )},
    { key: 'total_hits', header: 'Total Hits', render: (item: any) => item.total_hits.toLocaleString() },
    { key: 'blocked', header: 'Blocked', render: (item: any) => (
      <span className="text-neon-red">{item.blocked.toLocaleString()}</span>
    )},
    { key: 'passed', header: 'Passed', render: (item: any) => (
      <span className="text-neon-green">{item.passed.toLocaleString()}</span>
    )},
    { key: 'inbound', header: 'Inbound', render: (item: any) => item.inbound.toLocaleString() },
    { key: 'outbound', header: 'Outbound', render: (item: any) => item.outbound.toLocaleString() },
    { key: 'type', header: 'Type', render: (item: any) => {
      const isBlock = item.blocked > item.passed;
      return (
        <span className={`px-2 py-0.5 rounded text-xs ${
          isBlock ? 'bg-neon-red/20 text-neon-red' : 'bg-neon-green/20 text-neon-green'
        }`}>
          {isBlock ? 'BLOCK' : 'PASS'}
        </span>
      );
    }},
  ];

  const unexpectedPortColumns = [
    { key: 'port', header: 'Port', render: (item: any) => (
      <span className="font-mono text-neon-orange">{item.port}</span>
    )},
    { key: 'count', header: 'Unexpected Passes', render: (item: any) => item.count.toLocaleString() },
  ];

  if ((rulesLoading || unexpectedLoading) && !rules) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  const topRules = rules?.rules?.slice(0, 10) || [];
  const totalUnexpected = unexpected?.total_unexpected || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-neon-blue" />
            Firewall Rule Analysis
          </h2>
          <p className="text-sm text-text-muted mt-1">
            Rule hit statistics and misconfiguration detection
          </p>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(rules?.rules || [], 'firewall_rules')}
        />
      </div>

      {/* KPIs */}
      <KPIGrid>
        <KPICard
          title="Active Rules"
          value={rules?.rules?.length?.toString() || '0'}
          icon={<Shield className="w-5 h-5" />}
          color="blue"
        />
        <KPICard
          title="Block Rules"
          value={(rules?.rules?.filter((r: any) => r.blocked > r.passed).length || 0).toString()}
          icon={<Shield className="w-5 h-5" />}
          color="red"
        />
        <KPICard
          title="Pass Rules"
          value={(rules?.rules?.filter((r: any) => r.passed >= r.blocked).length || 0).toString()}
          icon={<Shield className="w-5 h-5" />}
          color="green"
        />
        <KPICard
          title="Unexpected Passes"
          value={totalUnexpected.toLocaleString()}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={totalUnexpected > 0 ? 'orange' : 'green'}
          subtitle={totalUnexpected === 0 ? 'All clear!' : 'Review needed'}
        />
      </KPIGrid>

      {/* Unexpected Passes Alert */}
      {totalUnexpected > 0 && (
        <div className="bg-neon-orange/10 border border-neon-orange/30 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-neon-orange flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-medium text-neon-orange">Unexpected Inbound Passes Detected</h3>
              <p className="text-sm text-text-muted mt-1">
                Found {totalUnexpected.toLocaleString()} inbound passes to ports NOT in your exposed honeypot list.
                This might indicate misconfigured NAT rules or unintended open ports.
              </p>
            </div>
          </div>
        </div>
      )}

      {totalUnexpected === 0 && (
        <div className="bg-neon-green/10 border border-neon-green/30 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-neon-green flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="font-medium text-neon-green">Security Configuration Verified</h3>
              <p className="text-sm text-text-muted mt-1">
                No unexpected inbound passes detected. Only your intentionally exposed honeypot ports are accepting traffic.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Rules Chart */}
        <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
          <h3 className="font-medium text-white mb-4">Top Rules by Hit Count</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topRules} layout="vertical">
                <XAxis type="number" stroke="#4b5563" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis
                  dataKey="rule_id"
                  type="category"
                  width={50}
                  stroke="#4b5563"
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                  tickFormatter={(v) => `#${v}`}
                />
                <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #2a2a4a' }} />
                <Legend />
                <Bar dataKey="blocked" stackId="a" fill="#ff3366" name="Blocked" />
                <Bar dataKey="passed" stackId="a" fill="#39ff14" name="Passed" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Unexpected Passes by Port */}
        {totalUnexpected > 0 && (
          <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
            <h3 className="font-medium text-white mb-4 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-neon-orange" />
              Unexpected Pass Ports
            </h3>
            <DataTable
              columns={unexpectedPortColumns}
              data={unexpected?.by_port || []}
              loading={unexpectedLoading}
              maxHeight="200px"
            />
          </div>
        )}

        {totalUnexpected === 0 && (
          <div className="bg-bg-card rounded-xl border border-bg-hover p-6 flex items-center justify-center">
            <div className="text-center">
              <CheckCircle className="w-12 h-12 text-neon-green mx-auto mb-3" />
              <p className="text-text-muted">No unexpected passes to non-exposed ports</p>
            </div>
          </div>
        )}
      </div>

      {/* All Rules Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover">
        <div className="p-4 border-b border-bg-hover">
          <h3 className="font-medium text-white">All Firewall Rules</h3>
        </div>
        <DataTable
          columns={ruleColumns}
          data={rules?.rules || []}
          loading={rulesLoading}
          maxHeight="500px"
        />
      </div>
    </div>
  );
}

