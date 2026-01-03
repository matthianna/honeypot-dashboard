import { useCallback } from 'react';
import { BarChart2, Clock, Map, Key, Network, TrendingUp, Zap, Shield, AlertTriangle, Users } from 'lucide-react';
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
import HoneypotPorts from '../components/HoneypotPorts';
import { useTimeRange } from '../hooks/useTimeRange';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { HeraldingCredential, HeraldingProtocolStats, GeoPoint } from '../types';

const COLORS = ['#ff3366', '#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ffff00'];

export default function Heralding() {
  const { timeRange, setTimeRange } = useTimeRange('24h');

  const { data: stats, loading: statsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: timeline, loading: timelineLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingTimeline(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: geo, loading: geoLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingGeo(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentials, loading: credentialsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentials(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: protocols, loading: protocolsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingProtocols(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: protocolDetails, loading: protocolDetailsLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingProtocolDetailedStats(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: attemptIntensity, loading: attemptIntensityLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingAttemptIntensity(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentialVelocity, loading: credentialVelocityLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentialVelocity(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: passwordAnalysis, loading: passwordAnalysisLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingPasswordAnalysis(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: bruteForce, loading: bruteForceLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingBruteForceDetection(timeRange), [timeRange]),
    [timeRange]
  );

  const { data: credentialReuse, loading: credentialReuseLoading } = useApiWithRefresh(
    useCallback(() => api.getHeraldingCredentialReuse(timeRange), [timeRange]),
    [timeRange]
  );

  const formatTimestamp = (timestamp: string) => {
    try {
      return new Date(timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return timestamp;
    }
  };

  const credentialColumns = [
    {
      key: 'protocol',
      header: 'Protocol',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-red uppercase">{item.protocol}</span>
      ),
    },
    {
      key: 'username',
      header: 'Username',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-blue">{item.username}</span>
      ),
    },
    {
      key: 'password',
      header: 'Password',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-orange">{item.password}</span>
      ),
    },
    {
      key: 'count',
      header: 'Attempts',
      render: (item: HeraldingCredential) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
      ),
    },
  ];

  const protocolColumns = [
    {
      key: 'protocol',
      header: 'Protocol',
      render: (item: HeraldingProtocolStats) => (
        <span className="font-mono text-neon-red uppercase">{item.protocol}</span>
      ),
    },
    {
      key: 'count',
      header: 'Events',
      render: (item: HeraldingProtocolStats) => (
        <span className="font-mono text-neon-green">{item.count.toLocaleString()}</span>
      ),
    },
    {
      key: 'unique_ips',
      header: 'Unique IPs',
      render: (item: HeraldingProtocolStats) => (
        <span className="font-mono text-neon-blue">{item.unique_ips.toLocaleString()}</span>
      ),
    },
  ];

  const tabs = [
    {
      id: 'overview',
      label: 'Overview',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <StatsCard title="Total Events" value={stats?.total_events || 0} color="red" loading={statsLoading} />
              <StatsCard title="Unique Attackers" value={stats?.unique_ips || 0} color="blue" loading={statsLoading} />
              <StatsCard title="Protocols" value={protocols?.length || 0} color="green" loading={protocolsLoading} />
            </div>
            <HoneypotPorts honeypot="heralding" />
          </div>

          <Card>
            <CardHeader title="Event Timeline" icon={<Clock className="w-5 h-5" />} />
            <CardContent>
              {timelineLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timeline?.data || []}>
                      <defs>
                        <linearGradient id="colorHeralding" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ff3366" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#ff3366" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                      <XAxis dataKey="timestamp" tickFormatter={formatTimestamp} stroke="#888888" />
                      <YAxis stroke="#888888" />
                      <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="count" stroke="#ff3366" fill="url(#colorHeralding)" strokeWidth={2} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Protocol Distribution Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Protocol Bar Chart */}
            <Card>
              <CardHeader title="Protocol Distribution" subtitle="Attack events by protocol" icon={<BarChart2 className="w-5 h-5" />} />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={protocols || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" />
                        <YAxis 
                          dataKey="protocol" 
                          type="category" 
                          stroke="#888888" 
                          width={80}
                          tick={{ fill: '#ff3366', fontSize: 11, fontFamily: 'monospace' }}
                        />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                          formatter={(value: number) => [value.toLocaleString(), 'Events']}
                        />
                        <Bar 
                          dataKey="count" 
                          fill="#ff3366"
                          radius={[0, 4, 4, 0]}
                        >
                          {(protocols || []).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Protocol Pie Chart */}
            <Card>
              <CardHeader title="Protocol Share" subtitle="Percentage breakdown" icon={<Network className="w-5 h-5" />} />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={protocols || []}
                          dataKey="count"
                          nameKey="protocol"
                          cx="50%"
                          cy="50%"
                          outerRadius={80}
                          label={({ protocol, percent }) => `${protocol} ${(percent * 100).toFixed(0)}%`}
                          labelLine={false}
                        >
                          {(protocols || []).map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
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

          <Card>
            <CardHeader title="Protocols" icon={<Network className="w-5 h-5" />} />
            <CardContent className="p-0">
              <DataTable columns={protocolColumns} data={protocols || []} loading={protocolsLoading} emptyMessage="No protocols found" />
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'credentials',
      label: 'Credentials',
      icon: <Key className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <Card>
            <CardHeader title="Top Credentials by Protocol" subtitle="Username/password combinations attempted" />
            <CardContent className="p-0">
              <DataTable columns={credentialColumns} data={credentials || []} loading={credentialsLoading} emptyMessage="No credentials found" />
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'password-analysis',
      label: 'Password Analysis',
      icon: <Shield className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {passwordAnalysisLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-blue">{passwordAnalysis?.total_unique_passwords || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Unique Passwords</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{passwordAnalysis?.total_attempts?.toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Total Attempts</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{passwordAnalysis?.avg_password_length || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Avg Password Length</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{passwordAnalysis?.common_password_percentage || 0}%</div>
                  <div className="text-xs text-text-secondary mt-1">Common Passwords</div>
                </div>
              </>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Password Strength Distribution */}
            <Card>
              <CardHeader title="Password Strength Distribution" subtitle="Security level of attempted passwords" icon={<Shield className="w-5 h-5" />} />
              <CardContent>
                {passwordAnalysisLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Very Weak', value: passwordAnalysis?.strength_distribution?.very_weak || 0, fill: '#ff3366' },
                            { name: 'Weak', value: passwordAnalysis?.strength_distribution?.weak || 0, fill: '#ff6600' },
                            { name: 'Moderate', value: passwordAnalysis?.strength_distribution?.moderate || 0, fill: '#ffff00' },
                            { name: 'Strong', value: passwordAnalysis?.strength_distribution?.strong || 0, fill: '#39ff14' },
                            { name: 'Very Strong', value: passwordAnalysis?.strength_distribution?.very_strong || 0, fill: '#00d4ff' },
                          ].filter(d => d.value > 0)}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          innerRadius={40}
                          outerRadius={80}
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }}
                          formatter={(value: number) => [value.toLocaleString(), 'Attempts']}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top Common Passwords from Wordlist */}
            <Card>
              <CardHeader title="Common Passwords Detected" subtitle="Matched against RockYou wordlist" icon={<AlertTriangle className="w-5 h-5 text-neon-red" />} />
              <CardContent>
                {passwordAnalysisLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (passwordAnalysis?.top_common_passwords?.length || 0) > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {passwordAnalysis?.top_common_passwords?.slice(0, 15).map((pwd, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg hover:bg-bg-hover transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="text-text-muted w-6 text-right">{idx + 1}.</span>
                          <code className="text-sm text-neon-red font-mono">{pwd.password}</code>
                          <span className="px-2 py-0.5 text-xs bg-neon-red/20 text-neon-red rounded">Common</span>
                        </div>
                        <span className="text-sm text-text-secondary">{pwd.count} uses</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-text-muted text-center py-4">No common passwords detected</p>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Top Passwords Table */}
          <Card>
            <CardHeader title="Top Passwords by Usage" subtitle="Most frequently attempted passwords" icon={<Key className="w-5 h-5" />} />
            <CardContent>
              {passwordAnalysisLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">#</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Password</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Strength</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Length</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Attempts</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {passwordAnalysis?.top_passwords?.slice(0, 20).map((pwd, idx) => {
                        const strengthColors: Record<string, string> = {
                          very_weak: 'text-neon-red bg-neon-red/20',
                          weak: 'text-neon-orange bg-neon-orange/20',
                          moderate: 'text-yellow-400 bg-yellow-400/20',
                          strong: 'text-neon-green bg-neon-green/20',
                          very_strong: 'text-neon-blue bg-neon-blue/20',
                        };
                        return (
                          <tr key={idx} className="hover:bg-bg-secondary transition-colors">
                            <td className="px-4 py-2 text-text-muted">{idx + 1}</td>
                            <td className="px-4 py-2">
                              <code className="font-mono text-neon-orange">{pwd.password}</code>
                              {pwd.strength.is_common && (
                                <span className="ml-2 px-2 py-0.5 text-xs bg-neon-red/20 text-neon-red rounded">Wordlist</span>
                              )}
                            </td>
                            <td className="px-4 py-2">
                              <span className={`px-2 py-1 text-xs rounded ${strengthColors[pwd.strength.category] || ''}`}>
                                {pwd.strength.category.replace('_', ' ')}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-text-secondary">{pwd.strength.length}</td>
                            <td className="px-4 py-2 font-mono text-neon-green">{pwd.count.toLocaleString()}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'brute-force',
      label: 'Brute Force',
      icon: <AlertTriangle className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {bruteForceLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{bruteForce?.total_brute_force_ips || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Brute Force IPs</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{bruteForce?.aggressive_attackers || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Aggressive (&gt;50/min)</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{bruteForce?.moderate_attackers || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Moderate (10-50/min)</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{bruteForce?.slow_attackers || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Slow (&lt;10/min)</div>
                </div>
              </>
            )}
          </div>

          {/* Brute Force Attackers Table */}
          <Card>
            <CardHeader title="Brute Force Attackers" subtitle="IPs with rapid credential attempts" icon={<AlertTriangle className="w-5 h-5 text-neon-red" />} />
            <CardContent>
              {bruteForceLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">IP</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Intensity</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Attempts</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Rate/min</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Sessions</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Protocols</th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Location</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {bruteForce?.brute_forcers?.slice(0, 25).map((attacker, idx) => {
                        const intensityColors: Record<string, string> = {
                          aggressive: 'text-neon-red bg-neon-red/20',
                          moderate: 'text-neon-orange bg-neon-orange/20',
                          slow: 'text-neon-green bg-neon-green/20',
                        };
                        return (
                          <tr key={idx} className="hover:bg-bg-secondary transition-colors">
                            <td className="px-4 py-2 font-mono text-neon-blue">{attacker.ip}</td>
                            <td className="px-4 py-2">
                              <span className={`px-2 py-1 text-xs rounded ${intensityColors[attacker.intensity] || ''}`}>
                                {attacker.intensity}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-right font-mono text-neon-red">{attacker.total_attempts.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right text-text-secondary">{attacker.attempts_per_minute}</td>
                            <td className="px-4 py-2 text-right text-text-secondary">{attacker.session_count}</td>
                            <td className="px-4 py-2">
                              <div className="flex gap-1 flex-wrap">
                                {attacker.protocols.slice(0, 3).map((proto) => (
                                  <span key={proto} className="px-2 py-0.5 text-xs bg-bg-secondary text-text-primary rounded">{proto}</span>
                                ))}
                              </div>
                            </td>
                            <td className="px-4 py-2 text-sm text-text-secondary">
                              {attacker.geo?.country || 'Unknown'}
                              {attacker.geo?.city && <span className="text-text-muted"> / {attacker.geo.city}</span>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Credential Reuse */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Passwords Used by Multiple IPs" subtitle="Coordinated attack indicator" icon={<Users className="w-5 h-5" />} />
              <CardContent>
                {credentialReuseLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (credentialReuse?.reused_passwords?.length || 0) > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {credentialReuse?.reused_passwords?.slice(0, 15).map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                        <code className="text-sm text-neon-orange font-mono">{item.password}</code>
                        <span className="px-2 py-1 text-xs bg-neon-purple/20 text-neon-purple rounded">
                          {item.ip_count} IPs
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-text-muted text-center py-4">No reused passwords detected</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Usernames Used by Multiple IPs" subtitle="Common target accounts" icon={<Users className="w-5 h-5" />} />
              <CardContent>
                {credentialReuseLoading ? (
                  <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (credentialReuse?.reused_usernames?.length || 0) > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {credentialReuse?.reused_usernames?.slice(0, 15).map((item, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                        <code className="text-sm text-neon-blue font-mono">{item.username}</code>
                        <span className="px-2 py-1 text-xs bg-neon-purple/20 text-neon-purple rounded">
                          {item.ip_count} IPs
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-text-muted text-center py-4">No reused usernames detected</p>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      ),
    },
    {
      id: 'protocols',
      label: 'Protocols',
      icon: <Network className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          {/* Protocol Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {protocolDetailsLoading ? (
              <div className="col-span-4 h-24 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-red">{protocolDetails?.protocols?.length || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Protocols Targeted</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-green">{protocolDetails?.protocols?.reduce((sum, p) => sum + p.sessions, 0).toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Total Sessions</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-blue">{protocolDetails?.protocols?.[0]?.protocol?.toUpperCase() || 'N/A'}</div>
                  <div className="text-xs text-text-secondary mt-1">Most Targeted</div>
                </div>
                <div className="p-4 bg-bg-card border border-bg-hover rounded-lg text-center">
                  <div className="text-2xl font-bold text-neon-orange">{protocolDetails?.protocols?.reduce((sum, p) => sum + p.total_auth_attempts, 0).toLocaleString() || 0}</div>
                  <div className="text-xs text-text-secondary mt-1">Auth Attempts</div>
                </div>
              </>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader title="Protocol Distribution" subtitle="Breakdown of attack attempts per protocol" />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={protocols || []} dataKey="count" nameKey="protocol" cx="50%" cy="50%" innerRadius={40} outerRadius={80} label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}>
                          {protocols?.map((_, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader title="Protocol Activity" subtitle="Comparison of attack volume by protocol" />
              <CardContent>
                {protocolsLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={protocols || []} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis type="number" stroke="#888888" />
                        <YAxis type="category" dataKey="protocol" stroke="#888888" tick={{ fill: '#888888', fontSize: 12 }} width={60} />
                        <Tooltip contentStyle={{ backgroundColor: '#1a1a25', border: '1px solid #252532', borderRadius: '8px' }} />
                        <Bar dataKey="count" fill="#ff3366" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Detailed Protocol Stats */}
          <Card>
            <CardHeader title="Protocol Details" subtitle="Detailed metrics per protocol" icon={<Network className="w-5 h-5" />} />
            <CardContent>
              {protocolDetailsLoading ? (
                <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full divide-y divide-bg-hover">
                    <thead className="bg-bg-card">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-text-secondary uppercase">Protocol</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Sessions</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Unique IPs</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Auth Attempts</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Avg Duration</th>
                        <th className="px-4 py-3 text-right text-xs font-medium text-text-secondary uppercase">Port</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-bg-hover/50">
                      {protocolDetails?.protocols?.map((proto, idx) => {
                        const totalSessions = protocolDetails?.protocols?.reduce((sum, p) => sum + p.sessions, 0) || 1;
                        const percentage = ((proto.sessions / totalSessions) * 100).toFixed(1);
                        return (
                          <tr key={idx} className="hover:bg-bg-secondary transition-colors">
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                                <span className="font-mono text-text-primary uppercase">{proto.protocol}</span>
                                <span className="text-xs text-text-muted">({percentage}%)</span>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-right font-mono text-neon-red">{proto.sessions.toLocaleString()}</td>
                            <td className="px-4 py-3 text-right font-mono text-neon-blue">{proto.unique_ips}</td>
                            <td className="px-4 py-3 text-right font-mono text-neon-green">{proto.total_auth_attempts.toLocaleString()}</td>
                            <td className="px-4 py-3 text-right font-mono text-text-secondary">{proto.avg_duration.toFixed(1)}s</td>
                            <td className="px-4 py-3 text-right font-mono text-neon-orange">{proto.ports.join(', ')}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      ),
    },
    {
      id: 'map',
      label: 'Geographic',
      icon: <Map className="w-4 h-4" />,
      content: (
        <Card>
          <CardHeader title="Attack Origins" />
          <CardContent>
            {geoLoading ? (
              <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
            ) : (
              <div className="space-y-2">
                {geo?.data?.slice(0, 15).map((item: GeoPoint, index: number) => (
                  <div key={item.country} className="flex items-center justify-between p-2 bg-bg-secondary rounded-lg">
                    <div className="flex items-center">
                      <div className="w-3 h-3 rounded-full mr-3" style={{ backgroundColor: COLORS[index % COLORS.length] }} />
                      <span className="text-text-primary">{item.country}</span>
                    </div>
                    <span className="font-mono text-neon-red">{item.count.toLocaleString()}</span>
                  </div>
                ))}
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
          {/* Protocol Detailed Stats */}
          <Card>
            <CardHeader title="Protocol Detailed Statistics" subtitle="Per-protocol metrics and performance" icon={<Network className="w-5 h-5" />} />
            <CardContent>
              {protocolDetailsLoading ? (
                <div className="h-48 flex items-center justify-center"><LoadingSpinner /></div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-text-secondary border-b border-bg-hover">
                        <th className="text-left py-2 px-3">Protocol</th>
                        <th className="text-right py-2 px-3">Sessions</th>
                        <th className="text-right py-2 px-3">Unique IPs</th>
                        <th className="text-right py-2 px-3">Avg Duration</th>
                        <th className="text-right py-2 px-3">Total Attempts</th>
                        <th className="text-right py-2 px-3">Avg Attempts</th>
                        <th className="text-left py-2 px-3">Ports</th>
                      </tr>
                    </thead>
                    <tbody>
                      {protocolDetails?.protocols?.map((p) => (
                        <tr key={p.protocol} className="border-b border-bg-hover hover:bg-bg-hover">
                          <td className="py-2 px-3 font-medium text-neon-red">{p.protocol.toUpperCase()}</td>
                          <td className="py-2 px-3 text-right font-mono">{p.sessions.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right font-mono text-neon-green">{p.unique_ips.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right text-text-secondary">{p.avg_duration}s</td>
                          <td className="py-2 px-3 text-right font-mono text-neon-blue">{p.total_auth_attempts.toLocaleString()}</td>
                          <td className="py-2 px-3 text-right text-text-secondary">{p.avg_auth_attempts}</td>
                          <td className="py-2 px-3">
                            <div className="flex gap-1">
                              {p.ports.slice(0, 3).map((port) => (
                                <span key={port} className="px-2 py-0.5 bg-bg-secondary rounded text-xs">{port}</span>
                              ))}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attempt Intensity */}
            <Card>
              <CardHeader title="Authentication Attempt Intensity" subtitle="Sessions and attempts over time" icon={<Zap className="w-5 h-5" />} />
              <CardContent>
                {attemptIntensityLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={attemptIntensity?.intensity || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis 
                          dataKey="timestamp" 
                          tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                          stroke="#888888"
                          tick={{ fill: '#888888', fontSize: 10 }}
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
                        <Legend />
                        <Line type="monotone" dataKey="sessions" name="Sessions" stroke="#ff3366" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="total_attempts" name="Auth Attempts" stroke="#39ff14" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="unique_ips" name="Unique IPs" stroke="#00d4ff" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Credential Velocity */}
            <Card>
              <CardHeader 
                title="Credential Brute-Force Velocity" 
                subtitle={`Total attempts: ${credentialVelocity?.total_attempts?.toLocaleString() || 0}`} 
                icon={<Key className="w-5 h-5" />} 
              />
              <CardContent>
                {credentialVelocityLoading ? (
                  <div className="h-64 flex items-center justify-center"><LoadingSpinner /></div>
                ) : (
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={credentialVelocity?.velocity || []}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#252532" />
                        <XAxis 
                          dataKey="timestamp" 
                          tickFormatter={(ts) => new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                          stroke="#888888"
                          tick={{ fill: '#888888', fontSize: 10 }}
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
                          formatter={(value: number, name: string) => [
                            name === 'rate_per_minute' ? `${value}/min` : value.toLocaleString(),
                            name === 'rate_per_minute' ? 'Rate' : 'Attempts'
                          ]}
                        />
                        <Area 
                          type="monotone" 
                          dataKey="rate_per_minute" 
                          stroke="#ff6600" 
                          fill="#ff6600" 
                          fillOpacity={0.3}
                          name="Rate/min"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}
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
          <h2 className="text-xl font-display font-semibold text-neon-red">Heralding Honeypot</h2>
          <p className="text-sm text-text-secondary mt-1">Multi-protocol credential capture honeypot</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>
      <Tabs tabs={tabs} defaultTab="overview" />
    </div>
  );
}

