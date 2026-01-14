import { useCallback, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart2,
  Clock,
  Map,
  Link2,
  Eye,
  Brain,
  TrendingUp,
  CheckCircle,
  XCircle,
  List,
  ChevronLeft,
  ChevronRight,
  Globe,
  Filter,
  Users,
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
import HoneypotMap from '../components/HoneypotMap';
import IPLink from '../components/IPLink';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { GalahPath, GeoPoint } from '../types';

const COLORS = ['#ff6600', '#39ff14', '#00d4ff', '#bf00ff', '#ff3366', '#ffff00'];

export default function Galah() {
  const navigate = useNavigate();
  const { timeRange, setTimeRange } = useTimeRange('24h');
  const [selectedInteractionId, setSelectedInteractionId] = useState<string | null>(null);
  
  // All Interactions state
  const [allInteractions, setAllInteractions] = useState<Array<Record<string, unknown>>>([]);
  const [allInteractionsTotal, setAllInteractionsTotal] = useState(0);
  const [allInteractionsOffset, setAllInteractionsOffset] = useState(0);
  const [allInteractionsLoading, setAllInteractionsLoading] = useState(false);
  const [interactionFilters, setInteractionFilters] = useState<{
    method: string;
    path: string;
    sourceIp: string;
  }>({ method: '', path: '', sourceIp: '' });
  const INTERACTIONS_PER_PAGE = 50;

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

  const { data: pathCategories, loading: pathCategoriesLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahPathCategories(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: sessionAnalysis, loading: sessionAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahSessionAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: engagementData, loading: engagementLoading } = useApiWithRefresh(
    useCallback(() => api.getGalahEngagementAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  // Fetch all interactions with pagination
  const fetchAllInteractions = useCallback(async (offset = 0) => {
    setAllInteractionsLoading(true);
    try {
      const filters = {
        method: interactionFilters.method || undefined,
        path: interactionFilters.path || undefined,
        sourceIp: interactionFilters.sourceIp || undefined,
      };
      const data = await api.getGalahAllInteractions(timeRange, offset, INTERACTIONS_PER_PAGE, filters);
      setAllInteractions(data.interactions);
      setAllInteractionsTotal(data.total);
      setAllInteractionsOffset(offset);
    } catch (error) {
      console.error('Failed to fetch all interactions:', error);
    } finally {
      setAllInteractionsLoading(false);
    }
  }, [timeRange, interactionFilters]);

  // Reset and fetch when time range or filters change
  useEffect(() => {
    // Only fetch if All Interactions tab is likely being viewed
    // Initial fetch will be triggered by tab change
  }, [timeRange, interactionFilters]);

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
              title="Total Paths" 
              value={stats?.total_events || 0} 
              color="red" 
              loading={statsLoading} 
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

          {/* Attacker Session Insights */}
          <Card className="border-2 border-neon-blue/20">
            <CardHeader 
              title="🔍 Attacker Session Insights" 
              subtitle="How attackers browse the honeypot - multiple page visits in a session"
              icon={<Users className="w-5 h-5 text-neon-blue" />}
            />
            <CardContent>
              {sessionAnalysisLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="space-y-4">
                  {/* Session Stats Summary */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-bg-secondary rounded-lg p-4 text-center">
                      <div className="text-3xl font-bold text-neon-blue">
                        {(sessionAnalysis as Record<string, unknown>)?.total_sessions?.toLocaleString() || 0}
                      </div>
                      <div className="text-xs text-text-secondary mt-1">Total Sessions</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-4 text-center">
                      <div className="text-3xl font-bold text-neon-green">
                        {((sessionAnalysis as Record<string, unknown>)?.multi_request_sessions as number)?.toLocaleString() || 0}
                      </div>
                      <div className="text-xs text-text-secondary mt-1">Multi-Page Sessions</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-4 text-center">
                      <div className="text-3xl font-bold text-neon-orange">
                        {(((sessionAnalysis as Record<string, unknown>)?.session_stats as Record<string, unknown>)?.avg_requests_per_session as number)?.toFixed(1) || '0'}
                      </div>
                      <div className="text-xs text-text-secondary mt-1">Avg Requests/Session</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-4 text-center">
                      <div className="text-3xl font-bold text-neon-purple">
                        {(((sessionAnalysis as Record<string, unknown>)?.session_stats as Record<string, unknown>)?.max_requests_in_session as number)?.toLocaleString() || 0}
                      </div>
                      <div className="text-xs text-text-secondary mt-1">Max Requests in Session</div>
                    </div>
                  </div>

                  {/* Top Multi-Request Sessions */}
                  <div className="bg-bg-secondary rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="font-medium text-text-primary">Top Multi-Page Sessions</h4>
                      <button
                        onClick={() => navigate('/galah/attackers')}
                        className="text-xs px-3 py-1 bg-neon-blue/20 text-neon-blue rounded hover:bg-neon-blue/30 transition-colors"
                      >
                        View All Sessions →
                      </button>
                    </div>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {(((sessionAnalysis as Record<string, unknown>)?.top_sessions as Array<{
                        session_id: string;
                        source_ip: string;
                        request_count: number;
                        unique_paths: number;
                        duration_seconds: number | null;
                        first_request: string;
                        country: string | null;
                      }>) || [])
                        .filter(s => s.request_count > 1)
                        .slice(0, 8)
                        .map((session, idx) => (
                          <div 
                            key={session.session_id} 
                            className="flex items-center justify-between p-3 bg-bg-primary rounded-lg hover:bg-bg-hover transition-colors cursor-pointer"
                            onClick={() => navigate('/galah/attackers')}
                          >
                            <div className="flex items-center gap-3">
                              <div className="w-8 h-8 rounded-full bg-neon-blue/20 flex items-center justify-center text-neon-blue font-bold text-sm">
                                {idx + 1}
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-sm text-text-primary">{session.source_ip}</span>
                                  {session.country && (
                                    <span className="text-xs text-text-muted flex items-center gap-1">
                                      <Globe className="w-3 h-3" />
                                      {session.country}
                                    </span>
                                  )}
                                </div>
                                <div className="text-xs text-text-muted mt-0.5">
                                  {new Date(session.first_request).toLocaleString()}
                                </div>
                              </div>
                            </div>
                            <div className="text-right">
                              <div className="flex items-center gap-2">
                                <span className="text-lg font-bold text-neon-green">{session.request_count}</span>
                                <span className="text-xs text-text-muted">pages</span>
                              </div>
                              <div className="text-xs text-text-secondary">
                                {session.unique_paths} unique paths
                              </div>
                              {session.duration_seconds && (
                                <div className="text-xs text-neon-orange">
                                  {session.duration_seconds < 60 
                                    ? `${Math.round(session.duration_seconds)}s` 
                                    : `${Math.floor(session.duration_seconds / 60)}m ${Math.round(session.duration_seconds % 60)}s`}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      {(((sessionAnalysis as Record<string, unknown>)?.top_sessions as unknown[]) || []).filter((s: unknown) => (s as {request_count: number}).request_count > 1).length === 0 && (
                        <div className="text-center py-6 text-text-muted text-sm">
                          No multi-page sessions found in this time range
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Insight Box */}
                  <div className="bg-neon-blue/10 border border-neon-blue/30 rounded-lg p-4">
                    <div className="flex items-start gap-3">
                      <Eye className="w-5 h-5 text-neon-blue flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-neon-blue mb-1">Session Analysis</h4>
                        <p className="text-sm text-text-secondary">
                          {(() => {
                            const totalSessions = (sessionAnalysis as Record<string, unknown>)?.total_sessions as number || 0;
                            const multiSessions = (sessionAnalysis as Record<string, unknown>)?.multi_request_sessions as number || 0;
                            const percentage = totalSessions > 0 ? ((multiSessions / totalSessions) * 100).toFixed(1) : 0;
                            return (
                              <>
                                <strong className="text-neon-green">{percentage}%</strong> of sessions involve multiple page visits, 
                                indicating attackers are exploring the honeypot beyond initial reconnaissance.
                                Click on "View All Sessions" to see complete browsing histories.
                              </>
                            );
                          })()}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Top 5 Attack Countries */}
          <Card>
            <CardHeader 
              title="Top Attack Countries" 
              subtitle={`${geo?.data?.length || 0} countries total`}
              icon={<Globe className="w-5 h-5" />}
            />
            <CardContent>
              {geoLoading ? (
                <div className="h-32 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  {geo?.data?.slice(0, 5).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="bg-bg-secondary rounded-lg p-3 text-center hover:bg-bg-hover transition-colors">
                      <div className="flex items-center justify-center gap-2 mb-1">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="font-medium text-text-primary text-sm truncate">{item.country}</span>
                      </div>
                      <div className="text-lg font-mono font-bold text-neon-orange">{item.count.toLocaleString()}</div>
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
      id: 'engagement',
      label: 'Engagement Analysis',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {engagementLoading ? (
            <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
          ) : engagementData ? (
            <>
              {/* Summary Stats */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4">
                <Card className="bg-gradient-to-br from-neon-orange/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-orange">
                      {((engagementData as Record<string, unknown>).summary as Record<string, number>)?.total_requests?.toLocaleString() || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Total Requests</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-blue/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-blue">
                      {((engagementData as Record<string, unknown>).summary as Record<string, number>)?.unique_attackers?.toLocaleString() || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Unique Attackers</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-green/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-green">
                      {((engagementData as Record<string, unknown>).summary as Record<string, number>)?.total_sessions?.toLocaleString() || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Total Sessions</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-neon-purple/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-neon-purple">
                      {((engagementData as Record<string, unknown>).summary as Record<string, number>)?.unique_paths_explored?.toLocaleString() || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Paths Explored</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-yellow-500/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-yellow-400">
                      {((engagementData as Record<string, unknown>).summary as Record<string, number>)?.avg_requests_per_attacker || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Avg Req/Attacker</div>
                  </CardContent>
                </Card>
                <Card className="bg-gradient-to-br from-pink-500/10 to-transparent">
                  <CardContent className="p-4">
                    <div className="text-2xl font-display font-bold text-pink-400">
                      {((engagementData as Record<string, unknown>).summary as Record<string, number>)?.avg_sessions_per_attacker || 0}
                    </div>
                    <div className="text-xs text-text-secondary">Avg Sessions/Attacker</div>
                  </CardContent>
                </Card>
              </div>

              {/* Return Visitors & Persistent Attackers */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="border-2 border-neon-green/20">
                  <CardHeader 
                    title="🔄 Return Visitors" 
                    subtitle="Attackers who initiated multiple sessions"
                  />
                  <CardContent>
                    <div className="flex items-center gap-6">
                      <div className="text-center">
                        <div className="text-4xl font-display font-bold text-neon-green">
                          {((engagementData as Record<string, unknown>).return_visitors as Record<string, number>)?.count || 0}
                        </div>
                        <div className="text-sm text-text-secondary">Attackers</div>
                      </div>
                      <div className="flex-1 space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className="text-text-secondary">Percentage</span>
                          <span className="font-bold text-neon-green">
                            {((engagementData as Record<string, unknown>).return_visitors as Record<string, number>)?.percentage || 0}%
                          </span>
                        </div>
                        <div className="h-3 bg-bg-secondary rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-neon-green rounded-full transition-all"
                            style={{ width: `${((engagementData as Record<string, unknown>).return_visitors as Record<string, number>)?.percentage || 0}%` }}
                          />
                        </div>
                        <p className="text-xs text-text-muted">
                          These attackers found the honeypot interesting enough to come back and explore more
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-2 border-neon-purple/20">
                  <CardHeader 
                    title="⏰ Persistent Attackers" 
                    subtitle="Attackers who returned after 24+ hours"
                  />
                  <CardContent>
                    <div className="flex items-center gap-6">
                      <div className="text-center">
                        <div className="text-4xl font-display font-bold text-neon-purple">
                          {((engagementData as Record<string, unknown>).persistent_attackers as Record<string, number>)?.count || 0}
                        </div>
                        <div className="text-sm text-text-secondary">Attackers</div>
                      </div>
                      <div className="flex-1 space-y-2">
                        <div className="flex justify-between text-sm">
                          <span className="text-text-secondary">Percentage</span>
                          <span className="font-bold text-neon-purple">
                            {((engagementData as Record<string, unknown>).persistent_attackers as Record<string, number>)?.percentage || 0}%
                          </span>
                        </div>
                        <div className="h-3 bg-bg-secondary rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-neon-purple rounded-full transition-all"
                            style={{ width: `${((engagementData as Record<string, unknown>).persistent_attackers as Record<string, number>)?.percentage || 0}%` }}
                          />
                        </div>
                        <p className="text-xs text-text-muted">
                          These attackers remembered the honeypot and came back on different days
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Session Depth & Time Wasted */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="Session Depth Distribution" subtitle="Requests per session" />
                  <CardContent>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={((engagementData as Record<string, unknown>).session_depth_distribution as Array<{depth: string; count: number}>) || []}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                          <XAxis dataKey="depth" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} />
                          <YAxis stroke="#888888" />
                          <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                          <Bar dataKey="count" fill="#ff6600" radius={[4, 4, 0, 0]}>
                            {(((engagementData as Record<string, unknown>).session_depth_distribution as Array<{depth: string; count: number}>) || []).map((_, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="mt-4 text-sm text-text-secondary">
                      <strong className="text-neon-orange">Insight:</strong> Sessions with more requests indicate attackers exploring multiple pages, searching for vulnerabilities.
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-2 border-neon-orange/20">
                  <CardHeader title="⏱️ Attacker Time Wasted" subtitle="How long attackers spent on the honeypot" />
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div className="bg-bg-secondary rounded-lg p-4 text-center">
                        <div className="text-3xl font-display font-bold text-neon-orange">
                          {(() => {
                            const seconds = ((engagementData as Record<string, unknown>).session_duration as Record<string, number>)?.avg_seconds || 0;
                            if (seconds < 60) return `${Math.round(seconds)}s`;
                            if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
                            return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
                          })()}
                        </div>
                        <div className="text-xs text-text-secondary">Avg Session Duration</div>
                      </div>
                      <div className="bg-bg-secondary rounded-lg p-4 text-center">
                        <div className="text-3xl font-display font-bold text-neon-green">
                          {(() => {
                            const seconds = ((engagementData as Record<string, unknown>).session_duration as Record<string, number>)?.max_seconds || 0;
                            if (seconds < 60) return `${Math.round(seconds)}s`;
                            if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
                            return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
                          })()}
                        </div>
                        <div className="text-xs text-text-secondary">Longest Session</div>
                      </div>
                    </div>
                    <div className="bg-gradient-to-r from-neon-orange/20 to-neon-green/20 rounded-lg p-4 text-center">
                      <div className="text-4xl font-display font-bold text-white mb-1">
                        {((engagementData as Record<string, unknown>).session_duration as Record<string, number>)?.total_time_wasted_hours?.toFixed(1) || 0}
                        <span className="text-lg text-text-secondary ml-1">hours</span>
                      </div>
                      <div className="text-sm text-text-secondary">Total Attacker Time Wasted</div>
                    </div>
                    <div className="mt-4 text-sm text-text-secondary">
                      <strong className="text-neon-green">Thesis Insight:</strong> The AI honeypot successfully wasted attacker resources by keeping them engaged with realistic responses.
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Top Attackers */}
              <Card>
                <CardHeader 
                  title="🎯 Top Engaged Attackers" 
                  subtitle="Most active attackers by request count"
                  action={
                    <button
                      onClick={() => navigate('/galah-attackers')}
                      className="text-sm text-neon-orange hover:underline"
                    >
                      View All Attackers →
                    </button>
                  }
                />
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-bg-hover">
                          <th className="text-left py-3 px-2 text-text-secondary">#</th>
                          <th className="text-left py-3 px-2 text-text-secondary">IP Address</th>
                          <th className="text-left py-3 px-2 text-text-secondary">Country</th>
                          <th className="text-right py-3 px-2 text-text-secondary">Requests</th>
                          <th className="text-right py-3 px-2 text-text-secondary">Sessions</th>
                          <th className="text-right py-3 px-2 text-text-secondary">Paths</th>
                          <th className="text-right py-3 px-2 text-text-secondary">Req/Session</th>
                          <th className="text-right py-3 px-2 text-text-secondary">Time Span</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(((engagementData as Record<string, unknown>).top_attackers as Array<{
                          ip: string;
                          total_requests: number;
                          sessions: number;
                          unique_paths: number;
                          time_span_hours: number;
                          country: string | null;
                          avg_requests_per_session: number;
                        }>) || []).slice(0, 15).map((attacker, idx) => (
                          <tr key={attacker.ip} className="border-b border-bg-hover/50 hover:bg-bg-hover/30">
                            <td className="py-3 px-2 text-text-muted">{idx + 1}</td>
                            <td className="py-3 px-2">
                              <IPLink ip={attacker.ip} />
                            </td>
                            <td className="py-3 px-2 text-text-secondary">{attacker.country || 'Unknown'}</td>
                            <td className="py-3 px-2 text-right font-mono font-bold text-neon-orange">{attacker.total_requests}</td>
                            <td className="py-3 px-2 text-right font-mono text-neon-blue">{attacker.sessions}</td>
                            <td className="py-3 px-2 text-right font-mono text-neon-green">{attacker.unique_paths}</td>
                            <td className="py-3 px-2 text-right font-mono text-neon-purple">{attacker.avg_requests_per_session}</td>
                            <td className="py-3 px-2 text-right text-text-secondary">
                              {attacker.time_span_hours < 1 
                                ? `${Math.round(attacker.time_span_hours * 60)}m` 
                                : attacker.time_span_hours < 24 
                                  ? `${Math.round(attacker.time_span_hours)}h`
                                  : `${Math.round(attacker.time_span_hours / 24)}d`}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>

              {/* HTTP Methods & Countries */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader title="HTTP Methods Used" />
                  <CardContent>
                    <div className="space-y-3">
                      {Object.entries((engagementData as Record<string, unknown>).methods as Record<string, number> || {}).sort((a, b) => b[1] - a[1]).map(([method, count], idx) => {
                        const total = Object.values((engagementData as Record<string, unknown>).methods as Record<string, number> || {}).reduce((a, b) => a + b, 0);
                        const percentage = total > 0 ? (count / total * 100).toFixed(1) : 0;
                        return (
                          <div key={method} className="flex items-center gap-3">
                            <span className={`font-mono text-sm w-16 px-2 py-1 rounded text-center ${
                              method === 'GET' ? 'bg-neon-green/20 text-neon-green' :
                              method === 'POST' ? 'bg-neon-orange/20 text-neon-orange' :
                              method === 'PUT' ? 'bg-neon-blue/20 text-neon-blue' :
                              method === 'DELETE' ? 'bg-neon-red/20 text-neon-red' :
                              'bg-neon-purple/20 text-neon-purple'
                            }`}>{method}</span>
                            <div className="flex-1 h-4 bg-bg-secondary rounded-full overflow-hidden">
                              <div 
                                className="h-full rounded-full transition-all"
                                style={{ 
                                  width: `${percentage}%`,
                                  backgroundColor: COLORS[idx % COLORS.length]
                                }}
                              />
                            </div>
                            <span className="font-mono text-sm text-text-muted w-20 text-right">{count.toLocaleString()}</span>
                            <span className="text-xs text-text-secondary w-12 text-right">{percentage}%</span>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader title="Top Attacking Countries" />
                  <CardContent>
                    <div className="space-y-3">
                      {(((engagementData as Record<string, unknown>).top_countries as Array<{country: string; count: number}>) || []).slice(0, 10).map((c, idx) => {
                        const maxCount = (((engagementData as Record<string, unknown>).top_countries as Array<{country: string; count: number}>) || [])[0]?.count || 1;
                        return (
                          <div key={c.country} className="flex items-center gap-3">
                            <span className="text-lg w-8">{idx < 3 ? ['🥇', '🥈', '🥉'][idx] : `${idx + 1}.`}</span>
                            <span className="text-sm text-text-primary flex-1 truncate">{c.country}</span>
                            <div className="w-32 h-3 bg-bg-secondary rounded-full overflow-hidden">
                              <div 
                                className="h-full rounded-full transition-all"
                                style={{ 
                                  width: `${(c.count / maxCount) * 100}%`,
                                  backgroundColor: COLORS[idx % COLORS.length]
                                }}
                              />
                            </div>
                            <span className="font-mono text-sm text-neon-orange w-16 text-right">{c.count.toLocaleString()}</span>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-text-secondary">No engagement data available</div>
          )}
        </div>
      ),
    },
    {
      id: 'all-interactions',
      label: 'All Interactions',
      icon: <List className="w-4 h-4" />,
      onSelect: () => {
        if (allInteractions.length === 0 && !allInteractionsLoading) {
          fetchAllInteractions(0);
        }
      },
      content: (
        <div className="space-y-6">
          {/* Filters */}
          <Card>
            <CardHeader title="Filter Interactions" icon={<Filter className="w-5 h-5" />} />
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <label className="block text-sm text-text-secondary mb-1">HTTP Method</label>
                  <select
                    value={interactionFilters.method}
                    onChange={(e) => setInteractionFilters(prev => ({ ...prev, method: e.target.value }))}
                    className="w-full bg-bg-primary border border-bg-hover rounded-lg px-3 py-2 text-text-primary focus:outline-none focus:border-neon-orange"
                  >
                    <option value="">All Methods</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="HEAD">HEAD</option>
                    <option value="OPTIONS">OPTIONS</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-text-secondary mb-1">Path Contains</label>
                  <input
                    type="text"
                    value={interactionFilters.path}
                    onChange={(e) => setInteractionFilters(prev => ({ ...prev, path: e.target.value }))}
                    placeholder="e.g., /admin, .php"
                    className="w-full bg-bg-primary border border-bg-hover rounded-lg px-3 py-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-neon-orange"
                  />
                </div>
                <div>
                  <label className="block text-sm text-text-secondary mb-1">Source IP</label>
                  <input
                    type="text"
                    value={interactionFilters.sourceIp}
                    onChange={(e) => setInteractionFilters(prev => ({ ...prev, sourceIp: e.target.value }))}
                    placeholder="e.g., 192.168.1.1"
                    className="w-full bg-bg-primary border border-bg-hover rounded-lg px-3 py-2 text-text-primary placeholder-text-muted focus:outline-none focus:border-neon-orange"
                  />
                </div>
                <div className="flex items-end gap-2">
                  <button
                    onClick={() => fetchAllInteractions(0)}
                    className="flex-1 bg-neon-orange text-black px-4 py-2 rounded-lg font-semibold hover:bg-neon-orange/80 transition-colors"
                  >
                    Apply Filters
                  </button>
                  <button
                    onClick={() => {
                      setInteractionFilters({ method: '', path: '', sourceIp: '' });
                      setTimeout(() => fetchAllInteractions(0), 100);
                    }}
                    className="px-4 py-2 bg-bg-hover text-text-secondary rounded-lg hover:text-text-primary transition-colors"
                  >
                    Clear
                  </button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Results Summary */}
          <div className="flex items-center justify-between">
            <div className="text-text-secondary">
              Showing <span className="text-neon-orange font-mono">{allInteractionsOffset + 1}</span> - <span className="text-neon-orange font-mono">{Math.min(allInteractionsOffset + INTERACTIONS_PER_PAGE, allInteractionsTotal)}</span> of <span className="text-neon-green font-mono">{allInteractionsTotal.toLocaleString()}</span> interactions
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => fetchAllInteractions(Math.max(0, allInteractionsOffset - INTERACTIONS_PER_PAGE))}
                disabled={allInteractionsOffset === 0 || allInteractionsLoading}
                className="p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <span className="text-sm text-text-secondary">
                Page {Math.floor(allInteractionsOffset / INTERACTIONS_PER_PAGE) + 1} of {Math.ceil(allInteractionsTotal / INTERACTIONS_PER_PAGE)}
              </span>
              <button
                onClick={() => fetchAllInteractions(allInteractionsOffset + INTERACTIONS_PER_PAGE)}
                disabled={allInteractionsOffset + INTERACTIONS_PER_PAGE >= allInteractionsTotal || allInteractionsLoading}
                className="p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Interactions Table */}
          <Card>
            <CardContent className="p-0">
              {allInteractionsLoading ? (
                <div className="h-96 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-bg-secondary border-b border-bg-hover">
                      <tr>
                        <th className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider px-4 py-3">Time</th>
                        <th className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider px-4 py-3">Source</th>
                        <th className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider px-4 py-3">Request</th>
                        <th className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider px-4 py-3">Response</th>
                        <th className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider px-4 py-3">Client</th>
                        <th className="text-left text-xs font-medium text-text-secondary uppercase tracking-wider px-4 py-3">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover">
                      {allInteractions.map((interaction) => {
                        const methodColors: Record<string, string> = {
                          GET: 'text-neon-green',
                          POST: 'text-neon-blue',
                          PUT: 'text-neon-orange',
                          DELETE: 'text-neon-red',
                          HEAD: 'text-neon-purple',
                        };
                        const method = interaction.method as string;
                        const isSuccess = interaction.message === 'successfulResponse';
                        const geo = interaction.geo as Record<string, unknown> | undefined;
                        
                        return (
                          <tr key={interaction.id as string} className="hover:bg-bg-hover/50 transition-colors">
                            <td className="px-4 py-3 whitespace-nowrap">
                              <div className="text-sm text-text-primary">{formatFullTimestamp(interaction.timestamp as string)}</div>
                              <div className="text-xs text-text-muted font-mono">{(interaction.session_id as string)?.slice(0, 12)}...</div>
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <IPLink ip={interaction.source_ip as string} />
                                {geo?.country_code ? (
                                  <span className="text-xs text-text-muted flex items-center gap-1">
                                    <Globe className="w-3 h-3" />
                                    {String(geo.country_code)}
                                  </span>
                                ) : null}
                              </div>
                              {geo?.city ? (
                                <div className="text-xs text-text-muted">{String(geo.city)}</div>
                              ) : null}
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <span className={`font-mono font-bold text-sm ${methodColors[method] || 'text-text-primary'}`}>
                                  {method}
                                </span>
                                <span className="font-mono text-xs text-text-secondary truncate max-w-[250px]" title={interaction.path as string}>
                                  {interaction.path as string}
                                </span>
                              </div>
                              {interaction.request_body ? (
                                <div className="text-xs text-text-muted mt-1 truncate max-w-[300px]" title={interaction.request_body as string}>
                                  Body: {String(interaction.request_body).slice(0, 50)}...
                                </div>
                              ) : null}
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                {isSuccess ? (
                                  <span className="flex items-center text-sm text-neon-green">
                                    <CheckCircle className="w-4 h-4 mr-1" />
                                    Success
                                  </span>
                                ) : (
                                  <span className="flex items-center text-sm text-neon-red">
                                    <XCircle className="w-4 h-4 mr-1" />
                                    Failed
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <div className="text-xs text-text-secondary truncate max-w-[150px]" title={interaction.user_agent as string}>
                                {String(interaction.browser || 'Unknown')}
                              </div>
                              <div className="text-xs text-text-muted">
                                {String(interaction.os || 'Unknown OS')}
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              <button
                                onClick={() => setSelectedInteractionId(interaction.id as string)}
                                className={`p-2 hover:bg-bg-hover rounded-lg transition-colors flex items-center gap-1 ${
                                  interaction.has_response_content 
                                    ? 'text-neon-green hover:text-neon-orange' 
                                    : 'text-text-muted hover:text-text-secondary'
                                }`}
                                title={interaction.has_response_content ? 'View AI-generated page' : 'View request details'}
                              >
                                <Eye className="w-4 h-4" />
                                <span className="text-xs">View</span>
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {allInteractions.length === 0 && !allInteractionsLoading && (
                    <div className="text-center py-12 text-text-secondary">
                      No interactions found. Try adjusting filters or time range.
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Pagination Footer */}
          {allInteractionsTotal > INTERACTIONS_PER_PAGE && (
            <div className="flex items-center justify-center gap-2">
              <button
                onClick={() => fetchAllInteractions(0)}
                disabled={allInteractionsOffset === 0 || allInteractionsLoading}
                className="px-3 py-1 text-sm bg-bg-secondary rounded hover:bg-bg-hover disabled:opacity-50 transition-colors"
              >
                First
              </button>
              <button
                onClick={() => fetchAllInteractions(Math.max(0, allInteractionsOffset - INTERACTIONS_PER_PAGE))}
                disabled={allInteractionsOffset === 0 || allInteractionsLoading}
                className="px-3 py-1 text-sm bg-bg-secondary rounded hover:bg-bg-hover disabled:opacity-50 transition-colors"
              >
                Previous
              </button>
              <span className="px-4 py-1 text-sm text-text-secondary">
                Page {Math.floor(allInteractionsOffset / INTERACTIONS_PER_PAGE) + 1} of {Math.ceil(allInteractionsTotal / INTERACTIONS_PER_PAGE)}
              </span>
              <button
                onClick={() => fetchAllInteractions(allInteractionsOffset + INTERACTIONS_PER_PAGE)}
                disabled={allInteractionsOffset + INTERACTIONS_PER_PAGE >= allInteractionsTotal || allInteractionsLoading}
                className="px-3 py-1 text-sm bg-bg-secondary rounded hover:bg-bg-hover disabled:opacity-50 transition-colors"
              >
                Next
              </button>
              <button
                onClick={() => fetchAllInteractions(Math.floor((allInteractionsTotal - 1) / INTERACTIONS_PER_PAGE) * INTERACTIONS_PER_PAGE)}
                disabled={allInteractionsOffset + INTERACTIONS_PER_PAGE >= allInteractionsTotal || allInteractionsLoading}
                className="px-3 py-1 text-sm bg-bg-secondary rounded hover:bg-bg-hover disabled:opacity-50 transition-colors"
              >
                Last
              </button>
            </div>
          )}
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
      id: 'paths',
      label: 'Paths',
      icon: <Link2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-orange">{paths?.length || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Unique Paths</div>
            </div>
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-green">{pathCategories?.categories?.length || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Categories</div>
            </div>
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-blue">{pathCategories?.categories?.[0]?.category || 'N/A'}</div>
              <div className="text-sm text-text-secondary mt-1">Top Category</div>
            </div>
            <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
              <div className="text-3xl font-bold text-neon-red">{paths?.reduce((sum, p) => sum + p.count, 0)?.toLocaleString() || 0}</div>
              <div className="text-sm text-text-secondary mt-1">Total Requests</div>
            </div>
          </div>

          {/* Path Categories - Main Feature */}
          <Card>
            <CardHeader 
              title="Path Categories" 
              subtitle="What attackers are looking for - grouped by attack type"
              icon={<Link2 className="w-5 h-5" />}
            />
            <CardContent>
              {pathCategoriesLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {pathCategories?.categories?.map((cat, index) => {
                    const totalRequests = pathCategories?.categories?.reduce((sum, c) => sum + c.count, 0) || 1;
                    const percentage = ((cat.count / totalRequests) * 100).toFixed(1);
                    return (
                      <div key={cat.category} className="bg-bg-secondary rounded-lg p-4 border border-bg-hover hover:border-neon-orange/30 transition-colors">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            <div className="w-4 h-4 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                            <span className="font-semibold text-text-primary">{cat.category}</span>
                          </div>
                          <span className="text-xs px-2 py-1 bg-neon-orange/20 text-neon-orange rounded-full">
                            {percentage}%
                          </span>
                        </div>
                        <div className="text-2xl font-mono font-bold text-neon-green mb-3">
                          {cat.count.toLocaleString()}
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs text-text-muted mb-2">Top paths:</div>
                          {cat.top_paths.slice(0, 4).map((p) => (
                            <div key={p.path} className="flex items-center justify-between text-xs">
                              <span className="font-mono text-text-secondary truncate max-w-[180px]" title={p.path}>
                                {p.path}
                              </span>
                              <span className="text-neon-green ml-2">{p.count}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Category Distribution Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Category Distribution" subtitle="Visual breakdown of attack types" />
              <CardContent>
                {pathCategoriesLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pathCategories?.categories?.slice(0, 8) || []}
                          dataKey="count"
                          nameKey="category"
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={90}
                          paddingAngle={2}
                        >
                          {pathCategories?.categories?.slice(0, 8).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                          formatter={(value: number) => [value.toLocaleString(), 'Requests']}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Category Bar Chart" subtitle="Comparison by volume" />
              <CardContent>
                {pathCategoriesLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={pathCategories?.categories?.slice(0, 8) || []} layout="vertical" margin={{ left: 10 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(0)}K` : v} />
                        <YAxis 
                          dataKey="category" 
                          type="category" 
                          stroke="#888888" 
                          width={100}
                          tick={{ fill: '#888888', fontSize: 11 }}
                        />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                          formatter={(value: number) => [value.toLocaleString(), 'Requests']}
                        />
                        <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                          {pathCategories?.categories?.slice(0, 8).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* All Targeted Paths List */}
          <Card>
            <CardHeader title="All Targeted Paths" subtitle="Complete list of requested URI paths" />
            <CardContent>
              {pathsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="space-y-2 max-h-[500px] overflow-y-auto">
                  {paths?.slice(0, 50).map((item: GalahPath, index: number) => (
                    <div key={item.path} className="flex items-center justify-between p-3 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <span className="w-8 h-8 flex items-center justify-center bg-bg-primary rounded-full text-sm font-mono text-text-muted">
                          {index + 1}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="font-mono text-sm text-neon-orange truncate" title={item.path}>{item.path}</div>
                          <div className="flex gap-2 mt-1">
                            {item.methods.map((method) => {
                              const methodColors: Record<string, string> = {
                                GET: 'bg-neon-green/20 text-neon-green',
                                POST: 'bg-neon-blue/20 text-neon-blue',
                                PUT: 'bg-neon-orange/20 text-neon-orange',
                                DELETE: 'bg-neon-red/20 text-neon-red',
                                HEAD: 'bg-neon-purple/20 text-neon-purple',
                              };
                              return (
                                <span key={method} className={`text-xs px-2 py-0.5 rounded font-mono ${methodColors[method] || 'bg-bg-card text-text-secondary'}`}>
                                  {method}
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                      <span className="font-mono text-neon-green ml-4 font-semibold">{item.count.toLocaleString()}</span>
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
      id: 'map',
      label: 'Attack Map',
      icon: <Map className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <HoneypotMap
            data={geo?.data?.map((g: GeoPoint) => ({ country: g.country, count: g.count })) || []}
            title="Galah Attack Origins"
            height="450px"
            accentColor="#ff6600"
            loading={geoLoading}
          />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Pie Chart */}
            <Card>
              <CardHeader title="Top Countries Distribution" subtitle="Request share by country" />
              <CardContent>
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie 
                        data={geo?.data?.slice(0, 6) || []} 
                        dataKey="count" 
                        nameKey="country" 
                        cx="50%" 
                        cy="50%" 
                        outerRadius={80} 
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                        {geo?.data?.slice(0, 6).map((_: unknown, index: number) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>

            {/* Country List */}
            <Card>
              <CardHeader title="Attack Countries" subtitle={`${geo?.data?.length || 0} countries detected`} />
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {geo?.data?.slice(0, 12).map((item: GeoPoint, index: number) => (
                    <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                      <div className="flex items-center gap-3">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                        <span className="text-text-primary font-medium">{item.country}</span>
                      </div>
                      <span className="font-mono text-neon-orange">{item.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
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
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/galah/attackers')}
            className="flex items-center gap-2 px-4 py-2 bg-neon-orange/20 text-neon-orange rounded-lg hover:bg-neon-orange/30 transition-colors border border-neon-orange/30"
          >
            <Users className="w-4 h-4" />
            Attacker Sessions
          </button>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
        </div>
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
