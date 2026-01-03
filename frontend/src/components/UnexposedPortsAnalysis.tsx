import { useCallback } from 'react';
import { AlertTriangle, Eye, EyeOff, Target, Shield, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import Card, { CardHeader, CardContent } from './Card';
import LoadingSpinner from './LoadingSpinner';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { TimeRange } from '../types';

interface UnexposedPortsAnalysisProps {
  timeRange: TimeRange;
}

export default function UnexposedPortsAnalysis({ timeRange }: UnexposedPortsAnalysisProps) {
  const { data, loading } = useApiWithRefresh(
    useCallback(() => api.getFirewallUnexposedAttacks(timeRange, 30), [timeRange]),
    [timeRange],
    60000
  );

  if (loading) {
    return (
      <Card>
        <CardHeader 
          title="Unexposed Port Analysis" 
          subtitle="Attacks on ports not monitored by honeypots"
          icon={<EyeOff className="w-5 h-5" />}
        />
        <CardContent className="h-64 flex items-center justify-center">
          <LoadingSpinner />
        </CardContent>
      </Card>
    );
  }

  if (!data) {
    return null;
  }

  const { summary, unexposed_ports, notable_findings } = data;

  // Prepare chart data - top 15 unexposed ports
  const chartData = unexposed_ports.slice(0, 15).map(p => ({
    name: `${p.port}`,
    label: p.service !== 'Unknown' ? p.service : `Port ${p.port}`,
    attacks: p.attack_count,
    attackers: p.unique_attackers,
  }));

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-neon-red/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-red/20">
                <EyeOff className="w-5 h-5 text-neon-red" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-red">
                  {summary.unexposed_percentage}%
                </div>
                <div className="text-xs text-text-secondary">Unexposed Attacks</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-orange/20">
                <Target className="w-5 h-5 text-neon-orange" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-orange">
                  {summary.unexposed_port_count}
                </div>
                <div className="text-xs text-text-secondary">Unexposed Ports Hit</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-green/20">
                <Eye className="w-5 h-5 text-neon-green" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-green">
                  {summary.exposed_port_count}
                </div>
                <div className="text-xs text-text-secondary">Exposed Ports</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-neon-blue/20">
                <Shield className="w-5 h-5 text-neon-blue" />
              </div>
              <div>
                <div className="text-2xl font-display font-bold text-neon-blue">
                  {summary.total_attacks.toLocaleString()}
                </div>
                <div className="text-xs text-text-secondary">Total Attacks</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Notable Findings */}
      {notable_findings.length > 0 && (
        <Card className="border-neon-orange/30">
          <CardHeader 
            title="Notable Findings" 
            subtitle="Interesting unexposed services being targeted"
            icon={<AlertTriangle className="w-5 h-5 text-neon-orange" />}
          />
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {notable_findings.slice(0, 6).map((finding) => (
                <div 
                  key={finding.port}
                  className="p-4 bg-bg-secondary rounded-lg border border-neon-orange/20"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-lg text-neon-orange">{finding.port}</span>
                      <span className="text-sm text-text-primary">{finding.service}</span>
                    </div>
                    <span className="text-xs px-2 py-1 rounded-full bg-neon-red/20 text-neon-red">
                      {finding.attack_count.toLocaleString()}
                    </span>
                  </div>
                  <p className="text-xs text-text-secondary">{finding.insight}</p>
                  <div className="mt-2 flex items-center gap-2 text-xs text-text-muted">
                    <span>{finding.unique_attackers} attackers</span>
                    <span>·</span>
                    <span>{finding.protocols.join(', ')}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bar Chart */}
        <Card>
          <CardHeader 
            title="Top Unexposed Ports" 
            subtitle="Most attacked ports with no honeypot coverage"
            icon={<Zap className="w-5 h-5" />}
          />
          <CardContent>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ left: 60 }}>
                  <XAxis type="number" stroke="#888888" />
                  <YAxis 
                    dataKey="label" 
                    type="category" 
                    stroke="#888888"
                    width={80}
                    tick={{ fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a1a25',
                      border: '1px solid #252532',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number, name: string) => [
                      value.toLocaleString(),
                      name === 'attacks' ? 'Attacks' : 'Unique Attackers'
                    ]}
                  />
                  <Bar dataKey="attacks" radius={[0, 4, 4, 0]}>
                    {chartData.map((_, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={index < 3 ? '#ff3366' : index < 7 ? '#ff6600' : '#bf00ff'} 
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Port Table */}
        <Card>
          <CardHeader 
            title="Unexposed Port Details" 
            subtitle="Complete list of unexposed ports under attack"
            icon={<EyeOff className="w-5 h-5" />}
          />
          <CardContent className="p-0">
            <div className="max-h-80 overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-bg-card border-b border-bg-hover">
                  <tr>
                    <th className="text-left py-3 px-4 text-text-secondary font-medium">Port</th>
                    <th className="text-left py-3 px-4 text-text-secondary font-medium">Service</th>
                    <th className="text-right py-3 px-4 text-text-secondary font-medium">Attacks</th>
                    <th className="text-right py-3 px-4 text-text-secondary font-medium">Attackers</th>
                    <th className="text-left py-3 px-4 text-text-secondary font-medium">Protocol</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-bg-hover">
                  {unexposed_ports.slice(0, 20).map((port) => (
                    <tr key={port.port} className="hover:bg-bg-hover/50">
                      <td className="py-2 px-4 font-mono text-neon-orange">{port.port}</td>
                      <td className="py-2 px-4 text-text-primary">{port.service}</td>
                      <td className="py-2 px-4 text-right font-mono text-neon-red">
                        {port.attack_count.toLocaleString()}
                      </td>
                      <td className="py-2 px-4 text-right font-mono text-neon-blue">
                        {port.unique_attackers}
                      </td>
                      <td className="py-2 px-4 text-text-muted uppercase text-xs">
                        {port.protocols.join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}






