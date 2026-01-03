import { useState, useCallback } from 'react';
import {
  FileText,
  BarChart2,
  Globe,
  TrendingUp,
  Zap,
  Shield,
  Terminal,
  Users,
  Clock,
  Target,
  Lightbulb,
  Download,
  Printer,
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import Tabs from '../components/Tabs';
import Card, { CardHeader, CardContent } from '../components/Card';
import LoadingSpinner from '../components/LoadingSpinner';
import TimeRangeSelector from '../components/TimeRangeSelector';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';

const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
};

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
};

const PIE_COLORS = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366', '#ffcc00'];

export default function Report() {
  const { timeRange, setTimeRange } = useTimeRange('30d');
  const [exportingPdf, setExportingPdf] = useState(false);

  // Fetch all report data
  const { data: summary, loading: summaryLoading } = useApiWithRefresh(
    useCallback(() => api.getThesisSummary(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: llmComparison, loading: llmLoading } = useApiWithRefresh(
    useCallback(() => api.getLLMComparison(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: patternAnalysis, loading: patternLoading } = useApiWithRefresh(
    useCallback(() => api.getPatternAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: trendAnalysis, loading: trendLoading } = useApiWithRefresh(
    useCallback(() => api.getTrendAnalysis(), []),
    []
  );

  const { data: geoAnalysis, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getGeographicAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: keyFindings, loading: findingsLoading } = useApiWithRefresh(
    useCallback(() => api.getKeyFindings(timeRange), [timeRange]),
    [timeRange]
  );

  const handleExportPDF = async () => {
    setExportingPdf(true);
    try {
      // Dynamic import for PDF libraries
      const html2canvas = (await import('html2canvas')).default;
      const { jsPDF } = await import('jspdf');
      
      const reportElement = document.getElementById('report-content');
      if (!reportElement) return;
      
      const canvas = await html2canvas(reportElement, {
        scale: 2,
        useCORS: true,
        logging: false,
      });
      
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`honeypot-thesis-report-${timeRange}.pdf`);
    } catch (error) {
      console.error('PDF export failed:', error);
    } finally {
      setExportingPdf(false);
    }
  };

  const tabs = [
    {
      id: 'summary',
      label: 'Executive Summary',
      icon: <FileText className="w-4 h-4" />,
      content: (
        <div className="space-y-6" id="report-content">
          {summaryLoading || findingsLoading ? (
            <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <>
              {/* Study Period Info */}
              <div className="bg-gradient-to-r from-neon-purple/20 to-neon-blue/20 rounded-xl border border-neon-purple/30 p-6">
                <div className="flex items-center gap-3 mb-4">
                  <Clock className="w-6 h-6 text-neon-purple" />
                  <h3 className="text-lg font-display font-bold text-text-primary">Study Period</h3>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <span className="text-text-muted">Start:</span>
                    <span className="ml-2 text-text-primary font-mono">
                      {summary?.study_period?.start ? new Date(summary.study_period.start).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-text-muted">End:</span>
                    <span className="ml-2 text-text-primary font-mono">
                      {summary?.study_period?.end ? new Date(summary.study_period.end).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-text-muted">Duration:</span>
                    <span className="ml-2 text-text-primary font-mono">{timeRange}</span>
                  </div>
                </div>
              </div>

              {/* Key Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="p-6 text-center">
                    <Zap className="w-8 h-8 text-neon-green mx-auto mb-2" />
                    <div className="text-3xl font-display font-bold text-neon-green">
                      {summary?.totals?.total_events?.toLocaleString() || 0}
                    </div>
                    <div className="text-sm text-text-secondary mt-1">Total Attack Events</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-6 text-center">
                    <Users className="w-8 h-8 text-neon-blue mx-auto mb-2" />
                    <div className="text-3xl font-display font-bold text-neon-blue">
                      {summary?.totals?.unique_ips?.toLocaleString() || 0}
                    </div>
                    <div className="text-sm text-text-secondary mt-1">Unique Attackers</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-6 text-center">
                    <Globe className="w-8 h-8 text-neon-orange mx-auto mb-2" />
                    <div className="text-3xl font-display font-bold text-neon-orange">
                      {summary?.totals?.countries || 0}
                    </div>
                    <div className="text-sm text-text-secondary mt-1">Countries</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-6 text-center">
                    <Shield className="w-8 h-8 text-neon-purple mx-auto mb-2" />
                    <div className="text-3xl font-display font-bold text-neon-purple">
                      {Object.keys(summary?.by_honeypot || {}).length}
                    </div>
                    <div className="text-sm text-text-secondary mt-1">Honeypots Active</div>
                  </CardContent>
                </Card>
              </div>

              {/* Honeypot Distribution */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="Attack Distribution by Honeypot" icon={<BarChart2 className="w-5 h-5" />} />
                  <CardContent>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={Object.entries(summary?.by_honeypot || {}).map(([name, stats], index) => ({
                              name: name.charAt(0).toUpperCase() + name.slice(1),
                              value: (stats as { events: number }).events,
                              color: HONEYPOT_COLORS[name] || PIE_COLORS[index],
                            }))}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={100}
                            paddingAngle={2}
                            dataKey="value"
                            label={({ name, percent }) => `${name} (${(percent * 100).toFixed(1)}%)`}
                          >
                            {Object.entries(summary?.by_honeypot || {}).map(([name], index) => (
                              <Cell key={name} fill={HONEYPOT_COLORS[name] || PIE_COLORS[index]} />
                            ))}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader title="Events per Honeypot" icon={<BarChart2 className="w-5 h-5" />} />
                  <CardContent>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={Object.entries(summary?.by_honeypot || {}).map(([name, stats]) => ({
                            name: name.charAt(0).toUpperCase() + name.slice(1),
                            events: (stats as { events: number }).events,
                            ips: (stats as { unique_ips: number }).unique_ips,
                          }))}
                          layout="vertical"
                        >
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis type="number" stroke="#888888" />
                          <YAxis dataKey="name" type="category" stroke="#888888" width={80} />
                          <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                          <Bar dataKey="events" fill="#39ff14" name="Events" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Key Findings */}
              <Card>
                <CardHeader title="Key Findings" subtitle="Auto-generated insights from data analysis" icon={<Lightbulb className="w-5 h-5" />} />
                <CardContent>
                  <div className="space-y-4">
                    {keyFindings?.findings?.map((finding: { category: string; finding: string; significance: string }, index: number) => (
                      <div key={index} className="flex gap-4 p-4 bg-bg-secondary rounded-lg border border-bg-hover">
                        <div className={`w-2 rounded-full ${
                          finding.significance === 'high' ? 'bg-neon-green' :
                          finding.significance === 'medium' ? 'bg-neon-orange' : 'bg-text-muted'
                        }`} />
                        <div className="flex-1">
                          <div className="text-xs text-text-muted uppercase tracking-wider mb-1">{finding.category}</div>
                          <p className="text-text-primary">{finding.finding}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      ),
    },
    {
      id: 'llm',
      label: 'LLM Comparison',
      icon: <Terminal className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {llmLoading ? (
            <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <>
              {/* Variant Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {llmComparison?.variants?.map((variant: {
                  variant: string;
                  display_name: string;
                  metrics: { total_events: number; sessions: number; commands_executed: number };
                  duration: { avg: number; median: number };
                  engagement: { login_rate: number; command_rate: number };
                }) => (
                  <Card key={variant.variant}>
                    <CardContent className="p-6">
                      <div className="flex items-center gap-3 mb-4">
                        <div className="w-4 h-4 rounded-full" style={{ backgroundColor: VARIANT_COLORS[variant.variant] }} />
                        <h3 className="font-display font-bold text-text-primary">{variant.display_name}</h3>
                      </div>
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-text-muted">Events</span>
                          <span className="font-mono text-text-primary">{variant.metrics.total_events.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-text-muted">Sessions</span>
                          <span className="font-mono text-text-primary">{variant.metrics.sessions.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-text-muted">Commands</span>
                          <span className="font-mono text-neon-green">{variant.metrics.commands_executed.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-text-muted">Avg Duration</span>
                          <span className="font-mono text-neon-blue">{variant.duration.avg}s</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-text-muted">Command Rate</span>
                          <span className="font-mono text-neon-orange">{variant.engagement.command_rate}%</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Comparison Charts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="Session Duration Comparison" subtitle="Average session duration by variant" />
                  <CardContent>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={llmComparison?.variants?.map((v: { display_name: string; duration: { avg: number; median: number; max: number } }) => ({
                          name: v.display_name,
                          avg: v.duration.avg,
                          median: v.duration.median,
                        })) || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis dataKey="name" stroke="#888888" />
                          <YAxis stroke="#888888" label={{ value: 'Seconds', angle: -90, position: 'insideLeft', fill: '#888888' }} />
                          <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                          <Legend />
                          <Bar dataKey="avg" name="Average" fill="#39ff14" />
                          <Bar dataKey="median" name="Median" fill="#00d4ff" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader title="Command Execution Comparison" subtitle="Commands executed per variant" />
                  <CardContent>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={llmComparison?.variants?.map((v: { display_name: string; metrics: { commands_executed: number; unique_commands: number } }) => ({
                          name: v.display_name,
                          total: v.metrics.commands_executed,
                          unique: v.metrics.unique_commands,
                        })) || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis dataKey="name" stroke="#888888" />
                          <YAxis stroke="#888888" />
                          <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                          <Legend />
                          <Bar dataKey="total" name="Total Commands" fill="#ff6600" />
                          <Bar dataKey="unique" name="Unique Commands" fill="#bf00ff" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Engagement Radar */}
              <Card>
                <CardHeader title="Engagement Metrics Radar" subtitle="Multi-dimensional comparison of variant effectiveness" />
                <CardContent>
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <RadarChart data={[
                        { metric: 'Login Rate', ...Object.fromEntries(llmComparison?.variants?.map((v: { variant: string; engagement: { login_rate: number } }) => [v.variant, v.engagement.login_rate]) || []) },
                        { metric: 'Success Rate', ...Object.fromEntries(llmComparison?.variants?.map((v: { variant: string; engagement: { success_rate: number } }) => [v.variant, v.engagement.success_rate]) || []) },
                        { metric: 'Command Rate', ...Object.fromEntries(llmComparison?.variants?.map((v: { variant: string; engagement: { command_rate: number } }) => [v.variant, v.engagement.command_rate]) || []) },
                      ]}>
                        <PolarGrid stroke="#252532" />
                        <PolarAngleAxis dataKey="metric" stroke="#888888" />
                        <PolarRadiusAxis stroke="#888888" />
                        {llmComparison?.variants?.map((v: { variant: string }) => (
                          <Radar
                            key={v.variant}
                            name={v.variant}
                            dataKey={v.variant}
                            stroke={VARIANT_COLORS[v.variant]}
                            fill={VARIANT_COLORS[v.variant]}
                            fillOpacity={0.3}
                          />
                        ))}
                        <Legend />
                        <Tooltip />
                      </RadarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>

              {/* Top Commands per Variant */}
              <Card>
                <CardHeader title="Top Commands by Variant" subtitle="Most frequently executed commands per honeypot variant" icon={<Terminal className="w-5 h-5" />} />
                <CardContent>
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    {llmComparison?.variants?.map((v: { variant: string; display_name: string; top_commands: Array<{ command: string; count: number }> }) => (
                      <div key={v.variant} className="bg-bg-secondary rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-3 pb-2 border-b border-bg-hover">
                          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: VARIANT_COLORS[v.variant] }} />
                          <span className="font-medium text-text-primary">{v.display_name}</span>
                        </div>
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                          {(v.top_commands || []).slice(0, 5).map((cmd, idx) => (
                            <div key={idx} className="flex justify-between gap-2 text-sm">
                              <code className="font-mono text-xs text-neon-green truncate flex-1" title={cmd.command}>
                                {cmd.command.slice(0, 40) || '(empty)'}...
                              </code>
                              <span className="font-mono text-text-muted">{cmd.count}</span>
                            </div>
                          ))}
                          {(!v.top_commands || v.top_commands.length === 0) && (
                            <div className="text-center text-text-muted text-sm py-4">No commands</div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      ),
    },
    {
      id: 'patterns',
      label: 'Attack Patterns',
      icon: <Target className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {patternLoading ? (
            <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <>
              {/* MITRE ATT&CK Techniques */}
              <Card>
                <CardHeader title="MITRE ATT&CK Techniques" subtitle="Attack techniques observed in honeypot data" icon={<Shield className="w-5 h-5" />} />
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    {patternAnalysis?.mitre_techniques?.map((tech: { technique_id: string; name: string; count: number }) => (
                      <div key={tech.technique_id} className="p-4 bg-bg-secondary rounded-lg border border-bg-hover">
                        <div className="font-mono text-neon-blue text-sm">{tech.technique_id}</div>
                        <div className="font-medium text-text-primary mt-1">{tech.name}</div>
                        <div className="text-2xl font-display font-bold text-neon-green mt-2">{tech.count.toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Command Categories */}
              <Card>
                <CardHeader title="Command Categories" subtitle="Breakdown of attacker commands by intent" />
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={Object.entries(patternAnalysis?.command_categories || {}).map(([cat, data]) => ({
                        category: cat.replace('_', ' '),
                        count: (data as { total_executions: number }).total_executions,
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="category" stroke="#888888" angle={-45} textAnchor="end" height={80} />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#ff6600" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>

              {/* Credentials Analysis */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="Top Usernames Attempted" />
                  <CardContent className="p-0">
                    <div className="max-h-64 overflow-y-auto">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 bg-bg-card">
                          <tr className="border-b border-bg-hover">
                            <th className="text-left py-2 px-4 text-text-secondary">#</th>
                            <th className="text-left py-2 px-4 text-text-secondary">Username</th>
                            <th className="text-right py-2 px-4 text-text-secondary">Attempts</th>
                          </tr>
                        </thead>
                        <tbody>
                          {patternAnalysis?.credentials?.top_usernames?.slice(0, 15).map((u: { username: string; count: number }, i: number) => (
                            <tr key={u.username} className="border-b border-bg-hover/50">
                              <td className="py-2 px-4 text-text-muted">{i + 1}</td>
                              <td className="py-2 px-4 font-mono text-neon-green">{u.username}</td>
                              <td className="py-2 px-4 text-right font-mono text-text-primary">{u.count.toLocaleString()}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader title="Top Passwords Attempted" />
                  <CardContent className="p-0">
                    <div className="max-h-64 overflow-y-auto">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 bg-bg-card">
                          <tr className="border-b border-bg-hover">
                            <th className="text-left py-2 px-4 text-text-secondary">#</th>
                            <th className="text-left py-2 px-4 text-text-secondary">Password</th>
                            <th className="text-right py-2 px-4 text-text-secondary">Attempts</th>
                          </tr>
                        </thead>
                        <tbody>
                          {patternAnalysis?.credentials?.top_passwords?.slice(0, 15).map((p: { password: string; count: number }, i: number) => (
                            <tr key={p.password} className="border-b border-bg-hover/50">
                              <td className="py-2 px-4 text-text-muted">{i + 1}</td>
                              <td className="py-2 px-4 font-mono text-neon-orange">{p.password}</td>
                              <td className="py-2 px-4 text-right font-mono text-text-primary">{p.count.toLocaleString()}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Protocol Distribution */}
              <Card>
                <CardHeader title="Protocol Distribution (Heralding)" subtitle="Attack attempts by protocol" />
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={patternAnalysis?.protocols?.map((p: { protocol: string; count: number }, i: number) => ({
                            name: p.protocol.toUpperCase(),
                            value: p.count,
                            color: PIE_COLORS[i % PIE_COLORS.length],
                          })) || []}
                          cx="50%"
                          cy="50%"
                          outerRadius={100}
                          dataKey="value"
                          label={({ name, percent }) => `${name} (${(percent * 100).toFixed(1)}%)`}
                        >
                          {patternAnalysis?.protocols?.map((_: unknown, i: number) => (
                            <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      ),
    },
    {
      id: 'geographic',
      label: 'Geographic',
      icon: <Globe className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {geoLoading ? (
            <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <>
              {/* Top Countries */}
              <Card>
                <CardHeader 
                  title="Top Attacking Countries" 
                  subtitle={`Attacks from ${geoAnalysis?.total_countries || 0} countries`}
                  icon={<Globe className="w-5 h-5" />} 
                />
                <CardContent>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Bar Chart */}
                    <div className="h-80">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={geoAnalysis?.top_countries?.slice(0, 10).map((c: { country: string; total: number }) => ({
                            country: c.country,
                            attacks: c.total,
                          })) || []}
                          layout="vertical"
                        >
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis type="number" stroke="#888888" />
                          <YAxis dataKey="country" type="category" stroke="#888888" width={120} />
                          <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                          <Bar dataKey="attacks" fill="#39ff14" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>

                    {/* Table */}
                    <div className="max-h-80 overflow-y-auto">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 bg-bg-card">
                          <tr className="border-b border-bg-hover">
                            <th className="text-left py-2 px-4 text-text-secondary">#</th>
                            <th className="text-left py-2 px-4 text-text-secondary">Country</th>
                            <th className="text-right py-2 px-4 text-text-secondary">Attacks</th>
                            <th className="text-right py-2 px-4 text-text-secondary">%</th>
                          </tr>
                        </thead>
                        <tbody>
                          {geoAnalysis?.top_countries?.slice(0, 15).map((c: { country: string; total: number }, i: number) => {
                            const totalAll = geoAnalysis?.top_countries?.reduce((sum: number, x: { total: number }) => sum + x.total, 0) || 1;
                            return (
                              <tr key={c.country} className="border-b border-bg-hover/50">
                                <td className="py-2 px-4 text-text-muted">{i + 1}</td>
                                <td className="py-2 px-4 text-text-primary">{c.country}</td>
                                <td className="py-2 px-4 text-right font-mono text-neon-green">{c.total.toLocaleString()}</td>
                                <td className="py-2 px-4 text-right font-mono text-text-muted">{((c.total / totalAll) * 100).toFixed(1)}%</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Country-Honeypot Matrix */}
              <Card>
                <CardHeader title="Country-Honeypot Distribution" subtitle="Which honeypots are targeted from each country" />
                <CardContent className="p-0 overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-bg-hover">
                        <th className="text-left py-3 px-4 text-text-secondary">Country</th>
                        {Object.keys(HONEYPOT_COLORS).map(hp => (
                          <th key={hp} className="text-right py-3 px-4 capitalize" style={{ color: HONEYPOT_COLORS[hp] }}>{hp}</th>
                        ))}
                        <th className="text-right py-3 px-4 text-text-secondary">Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {geoAnalysis?.top_countries?.slice(0, 10).map((c: { country: string; total: number; by_honeypot: Record<string, number> }) => (
                        <tr key={c.country} className="border-b border-bg-hover/50">
                          <td className="py-2 px-4 text-text-primary">{c.country}</td>
                          {Object.keys(HONEYPOT_COLORS).map(hp => (
                            <td key={hp} className="py-2 px-4 text-right font-mono text-text-muted">
                              {(c.by_honeypot?.[hp] || 0).toLocaleString()}
                            </td>
                          ))}
                          <td className="py-2 px-4 text-right font-mono font-bold text-text-primary">{c.total.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      ),
    },
    {
      id: 'trends',
      label: 'Time Analysis',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {trendLoading ? (
            <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
          ) : (
            <>
              {/* Weekly Trends */}
              <Card>
                <CardHeader title="Weekly Attack Trends" subtitle="Attack volume over the past 4 weeks" icon={<TrendingUp className="w-5 h-5" />} />
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={trendAnalysis?.weekly_trends?.reverse() || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="week" stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Legend />
                        <Area type="monotone" dataKey="total_events" name="Total Events" stroke="#39ff14" fill="#39ff14" fillOpacity={0.3} />
                        <Area type="monotone" dataKey="unique_ips" name="Unique IPs" stroke="#00d4ff" fill="#00d4ff" fillOpacity={0.3} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>

              {/* Hourly Pattern */}
              <Card>
                <CardHeader title="Hourly Attack Pattern" subtitle="Attack distribution by hour of day (UTC)" />
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={trendAnalysis?.hourly_pattern || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="hour" stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#ff6600" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 text-center">
                    <span className="text-text-muted">Peak Hour: </span>
                    <span className="font-mono text-neon-orange">{trendAnalysis?.peak_hour}:00 UTC</span>
                  </div>
                </CardContent>
              </Card>

              {/* Daily Pattern */}
              <Card>
                <CardHeader title="Daily Attack Pattern" subtitle="Attack distribution by day of week" />
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={trendAnalysis?.daily_pattern || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="day" stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#bf00ff" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 text-center">
                    <span className="text-text-muted">Peak Day: </span>
                    <span className="font-mono text-neon-purple">{trendAnalysis?.peak_day}</span>
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-neon-green/20 rounded-lg">
            <FileText className="w-6 h-6 text-neon-green" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold text-text-primary">Thesis Report</h1>
            <p className="text-text-secondary">Comprehensive analysis for academic research</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
          <button
            onClick={handleExportPDF}
            disabled={exportingPdf}
            className="flex items-center gap-2 px-4 py-2 bg-neon-green/20 text-neon-green rounded-lg hover:bg-neon-green/30 transition-colors disabled:opacity-50"
          >
            {exportingPdf ? (
              <LoadingSpinner />
            ) : (
              <>
                <Download className="w-4 h-4" />
                <span>Export PDF</span>
              </>
            )}
          </button>
          <button
            onClick={() => window.print()}
            className="flex items-center gap-2 px-4 py-2 bg-bg-secondary text-text-secondary rounded-lg hover:text-text-primary transition-colors"
          >
            <Printer className="w-4 h-4" />
            <span>Print</span>
          </button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs tabs={tabs} defaultTab="summary" />
    </div>
  );
}

