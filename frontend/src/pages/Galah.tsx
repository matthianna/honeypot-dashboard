import { useCallback, useState } from 'react';
import {
  BarChart2,
  Clock,
  Map,
  Link2,
  User,
  Eye,
  Brain,
  Shield,
  AlertTriangle,
  Terminal,
  TrendingUp,
  CheckCircle,
  XCircle,
  ExternalLink,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import TimeRangeSelector from '../components/TimeRangeSelector';
import Tabs from '../components/Tabs';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import GalahPreviewModal from '../components/GalahPreviewModal';
import HoneypotPorts from '../components/HoneypotPorts';
import IPLink from '../components/IPLink';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { GalahPath, GeoPoint } from '../types';

const COLORS = ['#ff6600', '#39ff14', '#00d4ff', '#bf00ff', '#ff3366', '#ffff00'];

export default function Galah() {
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [selectedInteractionId, setSelectedInteractionId] = useState<string | null>(null);

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: paths, loading: pathsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahPaths(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: interactions, loading: interactionsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahInteractions(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: aiAnalysis, loading: aiAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahAIAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: attackPatterns, loading: attackPatternsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahAttackPatterns(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: exploitIntel, loading: exploitIntelLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahExploitIntelligence(timeRange), [timeRange]),
    [timeRange]
  );

  // Session analysis data (available for future use)
  useApiWithRefresh(
    useCallback(() => api.getGalahSessionAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: successRateTrend, loading: successRateTrendLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahSuccessRateTrend(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: pathCategories, loading: pathCategoriesLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahPathCategories(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: requestMethods, loading: requestMethodsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahRequestMethods(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: sessionDepth, loading: sessionDepthLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahSessionDepth(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: userAgentAnalysis, loading: userAgentLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahUserAgentAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: httpFingerprints, loading: httpFingerprintsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahHttpFingerprints(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: llmStats, loading: llmStatsLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahLlmStats(timeRange), [timeRange]),
    [timeRange]
  );

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const formatFullTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch {
      return timestamp;
    }
  };

  const interactionColumns = [
    {
      key: 'timestamp',
      header: 'Time',
      render: (item: Record<string, unknown>) => (
        <span className="text-text-secondary text-sm">{formatFullTimestamp(item.timestamp as string)}</span>
      ),
    },
    {
      key: 'source_ip',
      header: 'Source IP',
      render: (item: Record<string, unknown>) => <IPLink ip={item.source_ip as string} />,
    },
    {
      key: 'method',
      header: 'Request',
      render: (item: Record<string, unknown>) => {
        const methodColors: Record<string, string> = {
          GET: 'text-neon-green',
          POST: 'text-neon-blue',
          PUT: 'text-neon-orange',
          DELETE: 'text-neon-red',
        };
        const method = item.method as string;
        return (
          <div className="flex items-center space-x-2">
            <span className={`font-mono font-bold ${methodColors[method] || 'text-text-primary'}`}>
              {method}
            </span>
            <span className="font-mono text-sm text-text-secondary truncate max-w-[200px]">
              {item.path as string}
            </span>
          </div>
        );
      },
    },
    {
      key: 'message',
      header: 'AI Response',
      render: (item: Record<string, unknown>) => {
        const isSuccess = item.message === 'successfulResponse';
        return (
          <span className={`flex items-center text-sm ${isSuccess ? 'text-neon-green' : 'text-neon-red'}`}>
            {isSuccess ? <CheckCircle className="w-4 h-4 mr-1" /> : <XCircle className="w-4 h-4 mr-1" />}
            {isSuccess ? 'Success' : 'Failed'}
          </span>
        );
      },
    },
    {
      key: 'actions',
      header: 'Preview',
      render: (item: Record<string, unknown>) => {
        const hasContent = item.has_response_content as boolean;
        return (
          <button
            onClick={() => setSelectedInteractionId(item.id as string)}
            className={`p-2 hover:bg-bg-hover rounded-lg transition-colors flex items-center space-x-1 ${
              hasContent 
                ? 'text-neon-green hover:text-neon-orange' 
                : 'text-text-muted hover:text-text-secondary'
            }`}
            title={hasContent ? 'View AI-generated page' : 'No response content available'}
          >
            <Eye className="w-4 h-4" />
            {hasContent && <span className="text-xs">View</span>}
          </button>
        );
      },
    },
  ];

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            <StatsCard title="Total Requests" value={stats?.total_events || 0} color="orange" loading={statsLoading} />
            <StatsCard title="Unique IPs" value={stats?.unique_ips || 0} color="blue" loading={statsLoading} />
            <StatsCard 
              title="AI Success Rate" 
              value={`${aiAnalysis?.success_rate || 0}%`} 
              color="green" 
              loading={aiAnalysisLoading} 
            />
            <StatsCard 
              title="CVEs Detected" 
              value={(exploitIntel?.summary as Record<string, number>)?.total_cves_detected || 0} 
              color="red" 
              loading={exploitIntelLoading} 
            />
            <HoneypotPorts honeypot="galah" />
          </div>

          <Card>
            <CardHeader title="Request Timeline" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorGalah" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff6600" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#ff6600" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#ff6600" fill="url(#colorGalah)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Recent Interactions" icon={<Eye className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable 
                columns={interactionColumns} 
                data={(interactions?.interactions || []) as Record<string, unknown>[]} 
                loading={interactionsLoading}
                emptyMessage="No interactions recorded"
              />
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'ai-analysis',
      label: 'AI Effectiveness',
      icon: <Brain className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Success Rate Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-bg-secondary rounded-xl p-6 border border-bg-hover">
              <div className="text-sm text-text-secondary mb-2">AI Response Success Rate</div>
              <div className="text-4xl font-display font-bold text-neon-green">
                {String(aiAnalysis?.success_rate || 0)}%
              </div>
              <div className="mt-2 text-sm text-text-muted">
                {String(aiAnalysis?.successful_responses || 0)} / {String(aiAnalysis?.total_requests || 0)} requests
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-6 border border-bg-hover">
              <div className="text-sm text-text-secondary mb-2">Successful Responses</div>
              <div className="text-4xl font-display font-bold text-neon-blue">
                {String(aiAnalysis?.successful_responses || 0)}
              </div>
              <div className="mt-2 text-sm text-text-muted flex items-center">
                <CheckCircle className="w-4 h-4 mr-1 text-neon-green" />
                AI generated convincing response
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-6 border border-bg-hover">
              <div className="text-sm text-text-secondary mb-2">Failed Responses</div>
              <div className="text-4xl font-display font-bold text-neon-red">
                {String(aiAnalysis?.failed_responses || 0)}
              </div>
              <div className="mt-2 text-sm text-text-muted flex items-center">
                <XCircle className="w-4 h-4 mr-1 text-neon-red" />
                500 Internal Server Error
              </div>
            </div>
          </div>

          {/* Success by HTTP Method */}
          <Card>
            <CardHeader title="AI Success Rate by HTTP Method" subtitle="How well the AI responds to different request types" icon={<TrendingUp className="w-5 h-5" />} />
            <CardContent>
              {aiAnalysisLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={(aiAnalysis?.by_method || []) as Array<{ method: string; success: number; failed: number; success_rate: number }>}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis dataKey="method" stroke="#888888" />
                        <YAxis stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Legend />
                        <Bar dataKey="success" name="Success" fill="#39ff14" stackId="a" />
                        <Bar dataKey="failed" name="Failed" fill="#ff3366" stackId="a" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="space-y-3">
                    {((aiAnalysis?.by_method || []) as Array<{ method: string; total: number; success_rate: number }>).map((m, i) => (
                      <div key={m.method} className="flex items-center justify-between p-3 bg-bg-card rounded-lg">
                        <div className="flex items-center">
                          <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                          <span className="font-mono font-bold text-text-primary">{m.method}</span>
                        </div>
                        <div className="text-right">
                          <div className="font-mono text-neon-green">{m.success_rate}%</div>
                          <div className="text-xs text-text-muted">{m.total} requests</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Success Over Time */}
          <Card>
            <CardHeader title="AI Response Success Over Time" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {aiAnalysisLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={(aiAnalysis?.timeline || []) as Array<{ timestamp: string; success: number; failed: number }>}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Legend />
                      <Line type="monotone" dataKey="success" name="Success" stroke="#39ff14" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="failed" name="Failed" stroke="#ff3366" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'attack-patterns',
      label: 'Attack Patterns',
      icon: <Shield className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Attack Categories */}
          <Card>
            <CardHeader title="Attack Categories" subtitle="Classification of attacks targeting the honeypot" icon={<AlertTriangle className="w-5 h-5" />} />
            <CardContent>
              {attackPatternsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={(attackPatterns?.attack_categories || []) as Array<{ category: string; count: number }>}
                          dataKey="count"
                          nameKey="category"
                          cx="50%"
                          cy="50%"
                          outerRadius={100}
                          label={({ percent }) => `${(percent * 100).toFixed(0)}%`}
                        >
                          {((attackPatterns?.attack_categories || []) as Array<unknown>).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="space-y-3">
                    {((attackPatterns?.attack_categories || []) as Array<{ category: string; description: string; count: number; example_paths: string[] }>).map((cat, i) => (
                      <div key={cat.category} className="bg-bg-card rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center">
                            <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                            <span className="font-semibold text-text-primary">{cat.description}</span>
                          </div>
                          <span className="font-mono text-neon-orange">{cat.count}</span>
                        </div>
                        {cat.example_paths.length > 0 && (
                          <div className="text-xs font-mono text-text-muted truncate">
                            {cat.example_paths[0]}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* User Agent Analysis */}
          <Card>
            <CardHeader title="User Agent Analysis" subtitle="Tools and clients used by attackers" icon={<User className="w-5 h-5" />} />
            <CardContent>
              {attackPatternsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart 
                        data={Object.entries((attackPatterns?.user_agents as Record<string, Record<string, number>>)?.categories || {}).map(([name, count]) => ({ name, count }))}
                        layout="vertical"
                        margin={{ left: 80 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" />
                        <YAxis type="category" dataKey="name" stroke="#888888" />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#ff6600" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {((attackPatterns?.user_agents as Record<string, Array<{ agent: string; count: number }>>)?.top_agents || []).slice(0, 10).map((ua) => (
                      <div key={ua.agent} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                        <span className="font-mono text-xs text-text-primary truncate max-w-[300px]">{ua.agent}</span>
                        <span className="font-mono text-neon-green ml-2">{ua.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'exploit-intel',
      label: 'Exploit Intelligence',
      icon: <AlertTriangle className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-bg-secondary rounded-xl p-6 border border-neon-red/30">
              <div className="text-sm text-text-secondary mb-2">CVEs Detected</div>
              <div className="text-4xl font-display font-bold text-neon-red">
                {(exploitIntel?.summary as Record<string, number>)?.total_cves_detected || 0}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-6 border border-neon-orange/30">
              <div className="text-sm text-text-secondary mb-2">Malware URLs</div>
              <div className="text-4xl font-display font-bold text-neon-orange">
                {(exploitIntel?.summary as Record<string, number>)?.total_malware_urls || 0}
              </div>
            </div>
            <div className="bg-bg-secondary rounded-xl p-6 border border-neon-purple/30">
              <div className="text-sm text-text-secondary mb-2">Command Injections</div>
              <div className="text-4xl font-display font-bold text-neon-purple">
                {(exploitIntel?.summary as Record<string, number>)?.total_command_injections || 0}
              </div>
            </div>
          </div>

          {/* Detected CVEs */}
          <Card>
            <CardHeader title="Detected CVE Exploits" subtitle="Known vulnerabilities being actively exploited" icon={<Shield className="w-5 h-5" />} />
            <CardContent>
              {exploitIntelLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="space-y-3">
                  {((exploitIntel?.detected_cves || []) as Array<{ cve: string; description: string; count: number; unique_sources: number; first_seen: string }>).map((cve) => (
                    <div key={cve.cve} className="bg-bg-card rounded-lg p-4 border-l-4 border-neon-red">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center">
                          <a 
                            href={`https://nvd.nist.gov/vuln/detail/${cve.cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono font-bold text-neon-red hover:underline flex items-center"
                          >
                            {cve.cve}
                            <ExternalLink className="w-3 h-3 ml-1" />
                          </a>
                        </div>
                        <span className="font-mono text-neon-orange">{cve.count} attempts</span>
                      </div>
                      <div className="text-sm text-text-primary mb-1">{cve.description}</div>
                      <div className="text-xs text-text-muted">
                        {cve.unique_sources} unique sources • First seen: {formatFullTimestamp(cve.first_seen)}
                      </div>
                    </div>
                  ))}
                  {((exploitIntel?.detected_cves || []) as Array<unknown>).length === 0 && (
                    <div className="text-center py-8 text-text-secondary">No CVE exploits detected in this time range</div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Malware URLs */}
          <Card>
            <CardHeader title="Malware Download URLs" subtitle="URLs found in attack payloads" icon={<ExternalLink className="w-5 h-5" />} />
            <CardContent>
              {exploitIntelLoading ? (
                <div className="h-32 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {((exploitIntel?.malware_urls || []) as Array<{ url: string; timestamp: string }>).map((item, i) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                      <code className="font-mono text-xs text-neon-orange break-all">{item.url}</code>
                      <span className="text-xs text-text-muted ml-4 whitespace-nowrap">{formatTimestamp(item.timestamp)}</span>
                    </div>
                  ))}
                  {((exploitIntel?.malware_urls || []) as Array<unknown>).length === 0 && (
                    <div className="text-center py-4 text-text-secondary">No malware URLs detected</div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Command Injections */}
          <Card>
            <CardHeader title="Command Injection Attempts" subtitle="Malicious commands in request payloads" icon={<Terminal className="w-5 h-5" />} />
            <CardContent>
              {exploitIntelLoading ? (
                <div className="h-32 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {((exploitIntel?.malicious_commands || []) as Array<{ path: string; source_ip: string; timestamp: string }>).map((cmd, i) => (
                    <div key={i} className="p-3 bg-bg-secondary rounded-lg">
                      <div className="flex items-center justify-between mb-1">
                        <IPLink ip={cmd.source_ip} />
                        <span className="text-xs text-text-muted">{formatTimestamp(cmd.timestamp)}</span>
                      </div>
                      <code className="font-mono text-xs text-neon-green break-all">{cmd.path}</code>
                    </div>
                  ))}
                  {((exploitIntel?.malicious_commands || []) as Array<unknown>).length === 0 && (
                    <div className="text-center py-4 text-text-secondary">No command injections detected</div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'paths',
      label: 'Paths',
      icon: <Link2 className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Targeted Paths" subtitle="Most requested URI paths" />
          <CardContent>
            {pathsLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto">
                {paths?.slice(0, 30).map((item: GalahPath) => (
                  <div key={item.path} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg">
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-sm text-neon-orange truncate">{item.path}</div>
                      <div className="flex gap-2 mt-1">
                        {item.methods.map((method) => (
                          <span key={method} className="text-xs px-2 py-0.5 bg-bg-card rounded text-text-secondary">{method}</span>
                        ))}
                      </div>
                    </div>
                    <span className="font-mono text-neon-green ml-4">{item.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'map',
      label: 'Geographic',
      icon: <Map className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Request Origins" />
          <CardContent>
            {geoLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={geo?.data?.slice(0, 6) || []} dataKey="count" nameKey="country" cx="50%" cy="50%" outerRadius={80} label>
                        {geo?.data?.slice(0, 6).map((_: unknown, index: number) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-2">
                  {geo?.data?.slice(0, 12).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                      <div className="flex items-center">
                        <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-orange">{item.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      ),
    },
    {
      id: 'analytics',
      label: 'Analytics',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* AI Success Rate Trend */}
          <Card>
            <CardHeader title="AI Response Success Rate Over Time" subtitle="Key thesis metric: LLM effectiveness trend" icon={<Brain className="w-5 h-5" />} />
            <CardContent>
              {successRateTrendLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={successRateTrend?.trend || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis 
                        dataKey="timestamp" 
                        tickFormatter={(ts) => new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                        stroke="#888888"
                        tick={{ fill: '#888888', fontSize: 10 }}
                      />
                      <YAxis 
                        yAxisId="left"
                        stroke="#888888" 
                        tick={{ fill: '#888888', fontSize: 10 }}
                      />
                      <YAxis 
                        yAxisId="right"
                        orientation="right"
                        domain={[0, 100]}
                        stroke="#888888" 
                        tick={{ fill: '#888888', fontSize: 10 }}
                        tickFormatter={(v) => `${v}%`}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1a1a25',
                          border: '1px solid #252532',
                          borderRadius: '8px',
                          color: '#e0e0e0',
                        }}
                        labelFormatter={(ts) => new Date(ts).toLocaleString()}
                      />
                      <Legend />
                      <Line yAxisId="left" type="monotone" dataKey="success" name="Success" stroke="#39ff14" strokeWidth={2} dot={false} />
                      <Line yAxisId="left" type="monotone" dataKey="failed" name="Failed" stroke="#ff3366" strokeWidth={2} dot={false} />
                      <Line yAxisId="right" type="monotone" dataKey="success_rate" name="Success Rate %" stroke="#ff6600" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Path Categories */}
            <Card>
              <CardHeader title="Attack Path Categories" subtitle="What attackers are looking for" icon={<Link2 className="w-5 h-5" />} />
              <CardContent>
                {pathCategoriesLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="space-y-3 max-h-80 overflow-y-auto">
                    {pathCategories?.categories?.map((cat, index) => (
                      <div key={cat.category} className="bg-bg-secondary rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center">
                            <div className="w-3 h-3 rounded-full mr-2" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                            <span className="font-medium text-text-primary">{cat.category}</span>
                          </div>
                          <span className="font-mono text-neon-orange">{cat.count.toLocaleString()}</span>
                        </div>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {cat.top_paths.slice(0, 3).map((p) => (
                            <span key={p.path} className="px-2 py-0.5 bg-bg-primary rounded text-xs font-mono text-text-secondary truncate max-w-[150px]" title={p.path}>
                              {p.path}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Request Methods */}
            <Card>
              <CardHeader title="Request Methods Analysis" subtitle="HTTP methods with success rates" icon={<Terminal className="w-5 h-5" />} />
              <CardContent>
                {requestMethodsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <>
                    <div className="h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={requestMethods?.methods || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis dataKey="method" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} />
                          <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#1a1a25',
                              border: '1px solid #252532',
                              borderRadius: '8px',
                              color: '#e0e0e0',
                            }}
                          />
                          <Legend />
                          <Bar dataKey="success" name="Success" fill="#39ff14" stackId="a" />
                          <Bar dataKey="failed" name="Failed" fill="#ff3366" stackId="a" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="mt-4 space-y-2">
                      {requestMethods?.methods?.map((m) => (
                        <div key={m.method} className="flex items-center justify-between text-sm">
                          <span className="font-mono text-neon-blue">{m.method}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-text-secondary">{m.count.toLocaleString()} total</span>
                            <span className={`font-bold ${m.success_rate > 70 ? 'text-neon-green' : m.success_rate > 40 ? 'text-neon-orange' : 'text-neon-red'}`}>
                              {m.success_rate}%
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Session Depth */}
          <Card>
            <CardHeader 
              title="Session Depth Analysis" 
              subtitle={`Total sessions: ${sessionDepth?.total_sessions?.toLocaleString() || 0}`} 
              icon={<User className="w-5 h-5" />} 
            />
            <CardContent>
              {sessionDepthLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                  {sessionDepth?.distribution?.map((d, index) => (
                    <div key={d.depth} className="bg-bg-secondary rounded-lg p-4 text-center">
                      <div className="text-2xl font-display font-bold" style={{ color: COLORS[index % COLORS.length] }}>
                        {d.count.toLocaleString()}
                      </div>
                      <div className="text-sm text-text-secondary mt-1">{d.depth} requests</div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'fingerprinting',
      label: 'Client Analysis',
      icon: <User className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Bot Detection & User Agent Analysis */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader 
                title="Bot vs Human Detection" 
                subtitle="Automated scanners vs browser-like clients"
              />
              <CardContent>
                {userAgentLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <>
                    {/* Bot/Human Ratio */}
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="bg-bg-secondary rounded-lg p-4 text-center">
                        <div className="text-2xl font-display font-bold text-neon-red">{userAgentAnalysis?.bot_detection?.bot_count?.toLocaleString() || 0}</div>
                        <div className="text-xs text-text-secondary">Bots ({userAgentAnalysis?.bot_detection?.bot_percentage || 0}%)</div>
                      </div>
                      <div className="bg-bg-secondary rounded-lg p-4 text-center">
                        <div className="text-2xl font-display font-bold text-neon-green">{userAgentAnalysis?.bot_detection?.human_count?.toLocaleString() || 0}</div>
                        <div className="text-xs text-text-secondary">Browser-like</div>
                      </div>
                    </div>

                    {/* Bot Tools */}
                    <h4 className="text-sm font-medium text-text-secondary mb-2">Identified Bot Tools</h4>
                    <div className="space-y-2 max-h-40 overflow-y-auto">
                      {userAgentAnalysis?.bot_detection?.tools?.map((tool) => (
                        <div key={tool.tool} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <span className="font-mono text-sm text-neon-orange">{tool.tool}</span>
                          <span className="font-mono text-neon-green">{tool.count}</span>
                        </div>
                      ))}
                      {(!userAgentAnalysis?.bot_detection?.tools || userAgentAnalysis.bot_detection.tools.length === 0) && (
                        <div className="text-center py-4 text-text-secondary text-sm">No bot tools detected</div>
                      )}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader 
                title="Browser Distribution" 
                subtitle="Client browsers identified"
              />
              <CardContent>
                {userAgentLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={userAgentAnalysis?.browsers?.slice(0, 6) || []}
                          cx="50%"
                          cy="50%"
                          innerRadius={40}
                          outerRadius={70}
                          paddingAngle={2}
                          dataKey="count"
                          nameKey="name"
                        >
                          {userAgentAnalysis?.browsers?.slice(0, 6).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                          formatter={(value: number, name: string) => [value.toLocaleString(), name]}
                        />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* OS Distribution */}
          <Card>
            <CardHeader 
              title="Operating System Distribution" 
              subtitle="Client OS breakdown"
            />
            <CardContent>
              {userAgentLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={userAgentAnalysis?.operating_systems?.slice(0, 10) || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="name" stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} angle={-45} textAnchor="end" height={60} />
                      <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#1a1a25',
                          border: '1px solid #252532',
                          borderRadius: '8px',
                          color: '#e0e0e0',
                        }}
                      />
                      <Bar dataKey="count" fill="#ff6600" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* HTTP Fingerprints */}
          <Card>
            <CardHeader 
              title="HTTP Client Fingerprinting" 
              subtitle={`${httpFingerprints?.unique_fingerprints || 0} unique fingerprints detected`}
            />
            <CardContent>
              {httpFingerprintsLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Protocol Versions */}
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">HTTP Protocol Versions</h4>
                    <div className="space-y-2">
                      {httpFingerprints?.protocol_versions?.map((pv) => (
                        <div key={pv.version} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <span className="font-mono text-neon-blue">{pv.version}</span>
                          <span className="font-mono text-neon-green">{pv.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Scanner Types by Header Pattern */}
                  <div>
                    <h4 className="text-sm font-medium text-text-secondary mb-3">Client Types by Headers</h4>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {httpFingerprints?.header_patterns?.slice(0, 10).map((hp, idx) => (
                        <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                          <div className="flex-1 min-w-0">
                            <span className="px-2 py-0.5 text-xs rounded bg-neon-purple/20 text-neon-purple mr-2">{hp.scanner_type}</span>
                            <span className="text-xs text-text-muted">{hp.header_count} headers</span>
                          </div>
                          <span className="font-mono text-neon-green">{hp.count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* LLM Stats */}
          <Card>
            <CardHeader 
              title="LLM Usage Statistics" 
              subtitle="AI-generated vs cached responses"
              icon={<Brain className="w-5 h-5" />}
            />
            <CardContent>
              {llmStatsLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <>
                  {/* Summary Stats */}
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-display font-bold text-neon-orange">{llmStats?.summary?.total_responses?.toLocaleString() || 0}</div>
                      <div className="text-xs text-text-secondary">Total Responses</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-display font-bold text-neon-green">{llmStats?.summary?.llm_generated?.toLocaleString() || 0}</div>
                      <div className="text-xs text-text-secondary">LLM Generated</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-display font-bold text-neon-blue">{llmStats?.summary?.cache_served?.toLocaleString() || 0}</div>
                      <div className="text-xs text-text-secondary">From Cache</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-display font-bold text-neon-purple">{llmStats?.summary?.llm_percentage || 0}%</div>
                      <div className="text-xs text-text-secondary">LLM Rate</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-display font-bold text-neon-green">{llmStats?.summary?.cache_hit_rate || 0}%</div>
                      <div className="text-xs text-text-secondary">Cache Hit Rate</div>
                    </div>
                  </div>

                  {/* LLM Timeline */}
                  <h4 className="text-sm font-medium text-text-secondary mb-3">LLM vs Cache Over Time</h4>
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={llmStats?.timeline || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis 
                          dataKey="timestamp" 
                          stroke="#888888" 
                          tick={{ fill: '#888888', fontSize: 10 }}
                          tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit' })}
                        />
                        <YAxis stroke="#888888" tick={{ fill: '#888888', fontSize: 10 }} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: '#1a1a25',
                            border: '1px solid #252532',
                            borderRadius: '8px',
                            color: '#e0e0e0',
                          }}
                          labelFormatter={(ts) => new Date(ts).toLocaleString()}
                        />
                        <Area type="monotone" dataKey="llm" stackId="1" fill="#39ff14" stroke="#39ff14" name="LLM" />
                        <Area type="monotone" dataKey="cache" stackId="1" fill="#00d4ff" stroke="#00d4ff" name="Cache" />
                        <Legend />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Models and Providers */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                    <div>
                      <h4 className="text-sm font-medium text-text-secondary mb-2">LLM Providers</h4>
                      {llmStats?.providers?.map((p) => (
                        <div key={p.provider} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg mb-2">
                          <span className="font-mono text-neon-orange">{p.provider}</span>
                          <span className="font-mono text-neon-green">{p.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-text-secondary mb-2">Models Used</h4>
                      {llmStats?.models?.map((m) => (
                        <div key={m.model} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg mb-2">
                          <span className="font-mono text-neon-blue">{m.model}</span>
                          <span className="font-mono text-neon-green">{m.count.toLocaleString()}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-neon-orange">Galah Web Honeypot</h2>
          <p className="text-sm text-text-secondary mt-1">LLM-powered web application honeypot with AI-generated responses</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />

      {selectedInteractionId && (
        <GalahPreviewModal
          interactionId={selectedInteractionId}
          onClose={() => setSelectedInteractionId(null)}
        />
      )}
    </div>
  );
}
