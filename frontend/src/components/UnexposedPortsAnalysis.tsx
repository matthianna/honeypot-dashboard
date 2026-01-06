import { useCallback } from 'react';
import { AlertTriangle, Eye, EyeOff, Target, Shield, Zap, TrendingUp } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie, Legend } from 'recharts';
import Card, { CardHeader, CardContent } from './Card';
import LoadingSpinner from './LoadingSpinner';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { TimeRange } from '../types';

interface UnexposedPortsAnalysisProps {
  timeRange: TimeRange;
}

const COLORS = ['#ff3366', '#ff6600', '#ffff00', '#39ff14', '#00d4ff', '#bf00ff'];

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

  // Prepare chart data - top 12 unexposed ports
  const chartData = unexposed_ports.slice(0, 12).map((p, index) => ({
    name: `${p.port}`,
    label: p.service !== 'Unknown' ? p.service : `Port ${p.port}`,
    attacks: p.attack_count,
    attackers: p.unique_attackers,
    color: COLORS[index % COLORS.length],
  }));

  // Pie chart data for exposed vs unexposed
  const pieData = [
    { name: 'Unexposed', value: summary.unexposed_percentage, color: '#ff3366' },
    { name: 'Exposed', value: 100 - summary.unexposed_percentage, color: '#39ff14' },
  ];

  return (
    <div className="space-y-6">
      {/* Summary Cards - Improved with larger text and better spacing */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-neon-red/10 to-transparent border-neon-red/30">
          <CardContent className="p-5">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-neon-red/20">
                <EyeOff className="w-6 h-6 text-neon-red" />
              </div>
              <div>
                <div className="text-3xl font-display font-bold text-neon-red">
                  {summary.unexposed_percentage}%
                </div>
                <div className="text-sm text-text-secondary mt-1">Unexposed Attacks</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent border-neon-orange/30">
          <CardContent className="p-5">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-neon-orange/20">
                <Target className="w-6 h-6 text-neon-orange" />
              </div>
              <div>
                <div className="text-3xl font-display font-bold text-neon-orange">
                  {summary.unexposed_port_count}
                </div>
                <div className="text-sm text-text-secondary mt-1">Unexposed Ports Hit</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-green/10 to-transparent border-neon-green/30">
          <CardContent className="p-5">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-neon-green/20">
                <Eye className="w-6 h-6 text-neon-green" />
              </div>
              <div>
                <div className="text-3xl font-display font-bold text-neon-green">
                  {summary.exposed_port_count}
                </div>
                <div className="text-sm text-text-secondary mt-1">Exposed Ports</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent border-neon-blue/30">
          <CardContent className="p-5">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-neon-blue/20">
                <Shield className="w-6 h-6 text-neon-blue" />
              </div>
              <div>
                <div className="text-3xl font-display font-bold text-neon-blue">
                  {summary.total_attacks.toLocaleString()}
                </div>
                <div className="text-sm text-text-secondary mt-1">Total Attacks</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Notable Findings - Enhanced styling */}
      {notable_findings.length > 0 && (
        <Card className="border-neon-orange/30">
          <CardHeader 
            title="Notable Findings" 
            subtitle="Interesting unexposed services being targeted"
            icon={<AlertTriangle className="w-5 h-5 text-neon-orange" />}
          />
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {notable_findings.slice(0, 6).map((finding, index) => (
                <div 
                  key={finding.port}
                  className="p-4 bg-bg-secondary rounded-xl border border-neon-orange/20 hover:border-neon-orange/40 transition-colors"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div 
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: COLORS[index % COLORS.length] }}
                      />
                      <span className="font-mono text-xl font-bold text-neon-orange">{finding.port}</span>
                      <span className="text-sm text-text-primary font-medium">{finding.service}</span>
                    </div>
                    <span className="text-sm px-3 py-1 rounded-full bg-neon-red/20 text-neon-red font-mono font-bold">
                      {finding.attack_count.toLocaleString()}
                    </span>
                  </div>
                  <p className="text-sm text-text-secondary mb-3">{finding.insight}</p>
                  <div className="flex items-center gap-3 text-xs text-text-muted">
                    <span className="flex items-center gap-1">
                      <TrendingUp className="w-3 h-3" />
                      {finding.unique_attackers} attackers
                    </span>
                    <span className="uppercase bg-bg-hover px-2 py-0.5 rounded">
                      {finding.protocols.join(', ')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Pie Chart - Coverage Overview */}
        <Card>
          <CardHeader 
            title="Coverage Overview" 
            subtitle="Exposed vs unexposed attack ratio"
            icon={<Shield className="w-5 h-5" />}
          />
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Legend 
                    verticalAlign="bottom"
                    formatter={(value, entry) => (
                      <span className="text-text-primary text-sm">
                        {value}: {(entry.payload as { value: number }).value.toFixed(1)}%
                      </span>
                    )}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a1a25',
                      border: '1px solid #252532',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number) => [`${value.toFixed(1)}%`, 'Percentage']}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Bar Chart - Enhanced */}
        <Card className="lg:col-span-2">
          <CardHeader 
            title="Top Unexposed Ports" 
            subtitle="Most attacked ports with no honeypot coverage"
            icon={<Zap className="w-5 h-5" />}
          />
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} layout="vertical" margin={{ left: 80, right: 20 }}>
                  <XAxis type="number" stroke="#888888" tickFormatter={(v) => v.toLocaleString()} />
                  <YAxis 
                    dataKey="label" 
                    type="category" 
                    stroke="#888888"
                    width={100}
                    tick={{ fontSize: 12, fill: '#aaaaaa' }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a1a25',
                      border: '1px solid #252532',
                      borderRadius: '8px',
                    }}
                    formatter={(value: number) => [value.toLocaleString(), 'Attacks']}
                    labelFormatter={(label) => `Service: ${label}`}
                  />
                  <Bar dataKey="attacks" radius={[0, 4, 4, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Port Table - Enhanced readability */}
      <Card>
        <CardHeader 
          title="Unexposed Port Details" 
          subtitle={`${unexposed_ports.length} unexposed ports under attack`}
          icon={<EyeOff className="w-5 h-5" />}
        />
        <CardContent className="p-0">
          <div className="max-h-96 overflow-y-auto">
            <table className="w-full">
              <thead className="sticky top-0 bg-bg-card border-b border-bg-hover">
                <tr>
                  <th className="text-left py-4 px-6 text-xs uppercase tracking-wider text-text-muted font-semibold">Port</th>
                  <th className="text-left py-4 px-6 text-xs uppercase tracking-wider text-text-muted font-semibold">Service</th>
                  <th className="text-right py-4 px-6 text-xs uppercase tracking-wider text-text-muted font-semibold">Attacks</th>
                  <th className="text-right py-4 px-6 text-xs uppercase tracking-wider text-text-muted font-semibold">Attackers</th>
                  <th className="text-left py-4 px-6 text-xs uppercase tracking-wider text-text-muted font-semibold">Protocol</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-bg-hover">
                {unexposed_ports.slice(0, 25).map((port, index) => (
                  <tr key={port.port} className="hover:bg-bg-hover/50 transition-colors">
                    <td className="py-4 px-6">
                      <div className="flex items-center gap-3">
                        <div 
                          className="w-2 h-2 rounded-full" 
                          style={{ backgroundColor: COLORS[index % COLORS.length] }}
                        />
                        <span className="font-mono text-lg font-bold text-neon-orange">{port.port}</span>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-text-primary font-medium">{port.service}</span>
                    </td>
                    <td className="py-4 px-6 text-right">
                      <span className="font-mono text-lg font-bold text-neon-red">
                        {port.attack_count.toLocaleString()}
                      </span>
                    </td>
                    <td className="py-4 px-6 text-right">
                      <span className="font-mono text-neon-blue">
                        {port.unique_attackers.toLocaleString()}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-xs uppercase px-2 py-1 bg-bg-secondary rounded text-text-muted">
                        {port.protocols.join(', ')}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
