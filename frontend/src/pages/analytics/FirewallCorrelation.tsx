import { useCallback, useEffect } from 'react';
import { GitCompare, ArrowRight, Shield, Terminal, Key, Command } from 'lucide-react';
import { useAnalytics } from './AnalyticsLayout';
import { KPIGrid, KPICard, ExportToolbar, exportToCSV } from '../../components/analytics';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

export default function FirewallCorrelation() {
  const { timeRange, setLastUpdated } = useAnalytics();

  const { data: funnel, loading: funnelLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCorrelationFunnel(timeRange),
    [timeRange]),
    [timeRange],
    60000
  );

  const { data: correlated, loading: correlatedLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCorrelationTop(timeRange, 30),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (funnel) setLastUpdated(new Date());
  }, [funnel, setLastUpdated]);

  const correlatedColumns = [
    { key: 'rank', header: '#', render: (_: any, i: number) => i + 1 },
    { key: 'ip', header: 'IP Address', render: (item: any) => <IPLink ip={item.ip} /> },
    { key: 'fw_total', header: 'FW Total', render: (item: any) => item.fw_total.toLocaleString() },
    { key: 'fw_blocked', header: 'FW Blocked', render: (item: any) => (
      <span className="text-neon-red">{item.fw_blocked.toLocaleString()}</span>
    )},
    { key: 'fw_ports', header: 'FW Ports' },
    { key: 'cowrie_sessions', header: 'Sessions' },
    { key: 'cowrie_logins', header: 'Logins' },
    { key: 'cowrie_commands', header: 'Commands', render: (item: any) => (
      <span className={item.cowrie_commands > 0 ? 'text-neon-green font-bold' : ''}>
        {item.cowrie_commands}
      </span>
    )},
  ];

  if ((funnelLoading || correlatedLoading) && !funnel) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  const funnelData = funnel?.funnel || {};
  const conversions = funnel?.conversion_rates || {};
  const correlations = funnel?.correlations || {};

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <GitCompare className="w-6 h-6 text-neon-purple" />
            Firewall → Honeypot Correlation
          </h2>
          <p className="text-sm text-text-muted mt-1">
            Track attackers from port scanning to honeypot exploitation
          </p>
        </div>
        <ExportToolbar
          onExportCSV={() => exportToCSV(correlated?.attackers || [], 'correlated_attackers')}
        />
      </div>

      {/* Attack Funnel Visualization */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
        <h3 className="font-medium text-white mb-6">Attack Funnel</h3>
        <div className="flex items-center justify-center gap-2 flex-wrap">
          {/* Stage 1: Closed Ports */}
          <div className="bg-neon-red/10 border border-neon-red/30 rounded-xl p-4 text-center min-w-[150px]">
            <Shield className="w-8 h-8 text-neon-red mx-auto mb-2" />
            <div className="text-2xl font-bold text-neon-red">{funnelData.closed_ports?.toLocaleString() || 0}</div>
            <div className="text-xs text-text-muted">Hit Closed Ports</div>
          </div>
          
          <ArrowRight className="w-6 h-6 text-text-muted" />
          
          {/* Stage 2: Exposed Ports */}
          <div className="bg-neon-orange/10 border border-neon-orange/30 rounded-xl p-4 text-center min-w-[150px]">
            <Terminal className="w-8 h-8 text-neon-orange mx-auto mb-2" />
            <div className="text-2xl font-bold text-neon-orange">{funnelData.exposed_ports?.toLocaleString() || 0}</div>
            <div className="text-xs text-text-muted">Hit Honeypots</div>
          </div>
          
          <ArrowRight className="w-6 h-6 text-text-muted" />
          
          {/* Stage 3: Authenticated */}
          <div className="bg-neon-yellow/10 border border-neon-yellow/30 rounded-xl p-4 text-center min-w-[150px]">
            <Key className="w-8 h-8 text-neon-yellow mx-auto mb-2" />
            <div className="text-2xl font-bold text-neon-yellow">{funnelData.authenticated?.toLocaleString() || 0}</div>
            <div className="text-xs text-text-muted">Authenticated</div>
          </div>
          
          <ArrowRight className="w-6 h-6 text-text-muted" />
          
          {/* Stage 4: Commands */}
          <div className="bg-neon-green/10 border border-neon-green/30 rounded-xl p-4 text-center min-w-[150px]">
            <Command className="w-8 h-8 text-neon-green mx-auto mb-2" />
            <div className="text-2xl font-bold text-neon-green">{funnelData.executed_commands?.toLocaleString() || 0}</div>
            <div className="text-xs text-text-muted">Ran Commands</div>
          </div>
        </div>

        {/* Conversion Rates */}
        <div className="mt-6 flex justify-center gap-8 text-sm">
          <div className="text-center">
            <div className="text-neon-orange font-bold">{conversions.exposed_to_auth_rate || 0}%</div>
            <div className="text-text-muted">Honeypot → Auth</div>
          </div>
          <div className="text-center">
            <div className="text-neon-yellow font-bold">{conversions.auth_to_cmd_rate || 0}%</div>
            <div className="text-text-muted">Auth → Commands</div>
          </div>
        </div>
      </div>

      {/* Cross-layer Correlations */}
      <KPIGrid>
        <KPICard
          title="Scanned → Honeypot"
          value={correlations.closed_to_exposed?.toString() || '0'}
          icon={<GitCompare className="w-5 h-5" />}
          color="orange"
          subtitle="IPs that scanned closed ports then hit honeypots"
        />
        <KPICard
          title="Scanned → Authenticated"
          value={correlations.closed_to_authenticated?.toString() || '0'}
          icon={<Key className="w-5 h-5" />}
          color="yellow"
          subtitle="IPs that scanned then successfully logged in"
        />
        <KPICard
          title="Scanned → Commands"
          value={correlations.closed_to_commands?.toString() || '0'}
          icon={<Command className="w-5 h-5" />}
          color="green"
          subtitle="IPs that scanned then executed commands"
        />
        <KPICard
          title="Total Correlated"
          value={correlated?.total_correlated?.toString() || '0'}
          icon={<GitCompare className="w-5 h-5" />}
          color="purple"
          subtitle="IPs appearing in both firewall and honeypot logs"
        />
      </KPIGrid>

      {/* Correlated Attackers Table */}
      <div className="bg-bg-card rounded-xl border border-bg-hover">
        <div className="p-4 border-b border-bg-hover">
          <h3 className="font-medium text-white">
            Correlated Attackers
            <span className="text-sm text-text-muted ml-2">
              (IPs seen in both firewall and honeypot logs)
            </span>
          </h3>
        </div>
        <DataTable
          columns={correlatedColumns}
          data={correlated?.attackers || []}
          loading={correlatedLoading}
          maxHeight="500px"
        />
      </div>

      {/* Insights */}
      <div className="bg-bg-card rounded-xl border border-bg-hover p-6">
        <h3 className="font-medium text-white mb-4">Key Insights</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="bg-bg-secondary rounded-lg p-4">
            <div className="font-medium text-neon-green mb-2">Reconnaissance Correlation</div>
            <p className="text-text-muted">
              {correlations.closed_to_exposed > 0 
                ? `${correlations.closed_to_exposed} attackers first scanned closed ports before hitting exposed honeypots, indicating methodical reconnaissance.`
                : 'No direct correlation found between port scanners and honeypot attackers in this time period.'}
            </p>
          </div>
          <div className="bg-bg-secondary rounded-lg p-4">
            <div className="font-medium text-neon-blue mb-2">Attack Sophistication</div>
            <p className="text-text-muted">
              {correlations.closed_to_commands > 0 
                ? `${correlations.closed_to_commands} attackers progressed from scanning to command execution - these are high-value IOCs for your thesis.`
                : 'Most attackers did not progress beyond initial scanning or authentication.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

