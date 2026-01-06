import { useCallback, useState, useMemo } from 'react';
import { 
  Shield, Target, AlertTriangle, Crosshair, ExternalLink, 
  Activity, Zap, Eye, ChevronDown, ChevronUp, Info
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import Card, { CardHeader, CardContent } from '../components/Card';
import StatsCard from '../components/StatsCard';
import DataTable from '../components/DataTable';
import LoadingSpinner from '../components/LoadingSpinner';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';

// Tactic colors matching MITRE ATT&CK official colors
const TACTIC_COLORS: Record<string, string> = {
  'Reconnaissance': '#ff3366',
  'Initial Access': '#ff6600',
  'Execution': '#39ff14',
  'Persistence': '#00d4ff',
  'Privilege Escalation': '#bf00ff',
  'Defense Evasion': '#9933ff',
  'Credential Access': '#ffcc00',
  'Discovery': '#00ff88',
  'Lateral Movement': '#ff00ff',
  'Collection': '#00ffff',
  'Command and Control': '#ff8800',
  'Exfiltration': '#ff0066',
  'Impact': '#ff0000',
};

// Severity colors
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff0000',
  high: '#ff6600',
  medium: '#ffcc00',
  low: '#39ff14',
};

// Tactics in kill chain order
const TACTICS_ORDER = [
  'Reconnaissance',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

// Honeypot icons
const HONEYPOT_ICONS: Record<string, string> = {
  cowrie: '🐚',
  dionaea: '🪴',
  galah: '🦜',
  rdpy: '🖥️',
  heralding: '📢',
  firewall: '🛡️',
};

interface Technique {
  id: string;
  name: string;
  tactic: string;
  count: number;
  severity?: string;
  sample_commands?: string[];
  url?: string;
}

interface TacticSummary {
  tactic: string;
  total: number;
  techniques: number;
}

export default function Mitre() {
  const timeRange = '30d'; // Fixed time range for comprehensive analysis
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'matrix' | 'table'>('matrix');

  const { data: summary, loading: summaryLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsMitreSummary(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  const { data: techniques, loading: techLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsMitreTechniques(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  // Group techniques by tactic for matrix view
  const techniquesByTactic = useMemo(() => {
    if (!techniques?.techniques) return {};
    const grouped: Record<string, Technique[]> = {};
    TACTICS_ORDER.forEach(tactic => { grouped[tactic] = []; });
    
    techniques.techniques.forEach((tech: Technique) => {
      if (grouped[tech.tactic]) {
        grouped[tech.tactic].push(tech);
      }
    });
    
    return grouped;
  }, [techniques]);

  // Filter techniques by selected tactic
  const filteredTechniques = useMemo(() => {
    if (!techniques?.techniques) return [];
    if (!selectedTactic) return techniques.techniques;
    return techniques.techniques.filter((t: Technique) => t.tactic === selectedTactic);
  }, [techniques, selectedTactic]);

  const techniqueColumns = [
    {
      key: 'id',
      header: 'ID',
      render: (item: Technique) => (
        <a 
          href={item.url || `https://attack.mitre.org/techniques/${item.id.replace('.', '/')}/`}
          target="_blank"
          rel="noopener noreferrer"
          className="font-mono text-neon-blue hover:underline flex items-center gap-1"
        >
          {item.id}
          <ExternalLink className="w-3 h-3" />
        </a>
      ),
    },
    { 
      key: 'name', 
      header: 'Technique',
      render: (item: Technique) => (
        <span className="font-medium text-white">{item.name}</span>
      ),
    },
    {
      key: 'tactic',
      header: 'Tactic',
      render: (item: Technique) => (
        <span
          className="px-2 py-1 rounded text-xs font-medium"
          style={{
            backgroundColor: `${TACTIC_COLORS[item.tactic] || '#888'}25`,
            color: TACTIC_COLORS[item.tactic] || '#888',
          }}
        >
          {item.tactic}
        </span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (item: Technique) => {
        const severity = item.severity || 'low';
        return (
          <span
            className="px-2 py-1 rounded text-xs font-bold uppercase"
            style={{
              backgroundColor: `${SEVERITY_COLORS[severity]}20`,
              color: SEVERITY_COLORS[severity],
            }}
          >
            {severity}
          </span>
        );
      },
    },
    {
      key: 'count',
      header: 'Events',
      render: (item: Technique) => (
        <span className="font-mono text-lg font-bold text-neon-orange">{item.count.toLocaleString()}</span>
      ),
    },
    {
      key: 'evidence',
      header: 'Sample Evidence',
      render: (item: Technique) => (
        <div className="max-w-sm">
          {item.sample_commands?.slice(0, 2).map((cmd: string, i: number) => (
            <div key={i} className="font-mono text-xs text-text-muted truncate bg-bg-secondary px-2 py-1 rounded mb-1">
              $ {cmd}
            </div>
          ))}
          {(item.sample_commands?.length || 0) > 2 && (
            <span className="text-xs text-text-muted">+{(item.sample_commands?.length || 0) - 2} more</span>
          )}
        </div>
      ),
    },
  ];

  // Render technique cell in matrix - improved readability
  const renderTechniqueCell = (tech: Technique) => {
    const isExpanded = expandedTechnique === tech.id;
    const severityColor = SEVERITY_COLORS[tech.severity || 'low'];
    
    return (
      <div
        key={tech.id}
        className={`p-3 rounded-lg border-2 cursor-pointer transition-all hover:scale-[1.02] ${
          isExpanded ? 'col-span-full' : ''
        }`}
        style={{
          backgroundColor: `${severityColor}10`,
          borderColor: `${severityColor}40`,
        }}
        onClick={() => setExpandedTechnique(isExpanded ? null : tech.id)}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="text-xs font-mono text-text-muted mb-1">{tech.id}</div>
            <div className="text-sm font-semibold text-white leading-tight" title={tech.name}>
              {tech.name}
            </div>
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <span 
              className="text-sm font-bold px-2 py-1 rounded-full min-w-[40px] text-center"
              style={{ backgroundColor: severityColor, color: '#000' }}
            >
              {tech.count}
            </span>
            {isExpanded ? <ChevronUp className="w-4 h-4 text-text-muted" /> : <ChevronDown className="w-4 h-4 text-text-muted" />}
          </div>
        </div>
        
        {isExpanded && (
          <div className="mt-4 pt-4 border-t border-white/10 space-y-3">
            <div className="flex items-center gap-4">
              <div>
                <span className="text-xs text-text-muted">Severity:</span>
                <span 
                  className="ml-2 text-sm font-bold uppercase"
                  style={{ color: severityColor }}
                >
                  {tech.severity || 'low'}
                </span>
              </div>
              <div>
                <span className="text-xs text-text-muted">Events:</span>
                <span className="ml-2 text-sm font-mono text-neon-orange">{tech.count.toLocaleString()}</span>
              </div>
            </div>
            {tech.sample_commands && tech.sample_commands.length > 0 && (
              <div>
                <div className="text-xs text-text-muted mb-2">Sample Commands:</div>
                <div className="bg-black/40 rounded-lg p-3 max-h-40 overflow-y-auto space-y-1">
                  {tech.sample_commands.slice(0, 5).map((cmd, i) => (
                    <div key={i} className="font-mono text-xs text-neon-green">$ {cmd}</div>
                  ))}
                </div>
              </div>
            )}
            <a
              href={tech.url || `https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-neon-blue hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              View on MITRE ATT&CK <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-display font-semibold text-white flex items-center gap-2">
            <Crosshair className="w-6 h-6 text-neon-red" />
            MITRE ATT&CK Analysis
          </h2>
          <p className="text-sm text-text-secondary mt-1">
            Mapping observed attacker behavior to the MITRE ATT&CK framework (last 30 days)
          </p>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Techniques Detected"
          value={summary?.summary?.detected || 0}
          icon={<Target className="w-5 h-5" />}
          color="green"
          loading={summaryLoading}
        />
        <StatsCard
          title="Total Events"
          value={summary?.summary?.events || 0}
          icon={<Activity className="w-5 h-5" />}
          color="orange"
          loading={summaryLoading}
        />
        <StatsCard
          title="Active Tactics"
          value={summary?.tactics?.filter((t: TacticSummary) => t.total > 0).length || 0}
          icon={<Shield className="w-5 h-5" />}
          color="blue"
          loading={summaryLoading}
        />
        <StatsCard
          title="Top Technique"
          value={summary?.techniques?.[0]?.name || '-'}
          icon={<Zap className="w-5 h-5" />}
          color="red"
          loading={summaryLoading}
        />
      </div>

      {/* View Toggle */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 bg-bg-secondary rounded-lg p-1">
              {[
                { key: 'matrix', label: 'Matrix View', icon: <Eye className="w-4 h-4" /> },
                { key: 'table', label: 'Table View', icon: <Activity className="w-4 h-4" /> },
              ].map(({ key, label, icon }) => (
                <button
                  key={key}
                  onClick={() => setViewMode(key as 'matrix' | 'table')}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
                    viewMode === key
                      ? 'bg-neon-green text-bg-primary'
                      : 'text-text-secondary hover:text-text-primary hover:bg-bg-hover'
                  }`}
                >
                  {icon}
                  {label}
                </button>
              ))}
            </div>
            {selectedTactic && (
              <button
                onClick={() => setSelectedTactic(null)}
                className="text-sm text-neon-red hover:underline flex items-center gap-1"
              >
                <AlertTriangle className="w-4 h-4" />
                Clear Filter: {selectedTactic}
              </button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Matrix View - Improved */}
      {viewMode === 'matrix' && (
        <Card>
          <CardHeader
            title="MITRE ATT&CK Matrix"
            subtitle="Click on any tactic header to filter, or technique cell to expand details"
            icon={<Shield className="w-5 h-5" />}
          />
          <CardContent>
            {techLoading ? (
              <div className="h-96 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="overflow-x-auto pb-4">
                <div className="flex gap-3 min-w-max">
                  {TACTICS_ORDER.map((tactic) => {
                    const tacticTechniques = techniquesByTactic[tactic] || [];
                    const tacticTotal = tacticTechniques.reduce((sum, t) => sum + t.count, 0);
                    const isSelected = selectedTactic === tactic;
                    const hasData = tacticTechniques.length > 0;
                    
                    return (
                      <div 
                        key={tactic} 
                        className={`w-56 flex-shrink-0 ${!hasData ? 'opacity-50' : ''}`}
                      >
                        {/* Tactic Header - Improved */}
                        <button
                          onClick={() => setSelectedTactic(isSelected ? null : tactic)}
                          disabled={!hasData}
                          className={`w-full p-3 rounded-t-xl text-center transition-all ${
                            isSelected ? 'ring-2 ring-white shadow-lg' : ''
                          } ${hasData ? 'hover:brightness-110 cursor-pointer' : 'cursor-not-allowed'}`}
                          style={{ 
                            backgroundColor: TACTIC_COLORS[tactic],
                            color: '#000',
                          }}
                        >
                          <div className="text-xs font-bold uppercase tracking-wide mb-1">
                            {tactic}
                          </div>
                          <div className="flex items-center justify-center gap-2 text-sm">
                            <span className="font-bold">{tacticTechniques.length}</span>
                            <span className="opacity-75">techniques</span>
                          </div>
                          {tacticTotal > 0 && (
                            <div className="text-xs mt-1 opacity-75">
                              {tacticTotal.toLocaleString()} events
                            </div>
                          )}
                        </button>
                        
                        {/* Techniques Column - Improved */}
                        <div className="bg-bg-secondary/60 rounded-b-xl p-3 space-y-2 min-h-[250px] max-h-[500px] overflow-y-auto border border-bg-hover border-t-0">
                          {tacticTechniques.length > 0 ? (
                            tacticTechniques
                              .sort((a, b) => b.count - a.count)
                              .map(tech => renderTechniqueCell(tech))
                          ) : (
                            <div className="text-center text-text-muted text-sm py-8">
                              <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                              No techniques detected
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Table View - Improved */}
      {viewMode === 'table' && (
        <Card>
          <CardHeader
            title="Technique Details"
            subtitle={selectedTactic ? `Filtered by: ${selectedTactic}` : `All ${filteredTechniques.length} detected techniques with evidence`}
            icon={<AlertTriangle className="w-5 h-5" />}
          />
          <CardContent>
            <DataTable
              columns={techniqueColumns}
              data={filteredTechniques}
              loading={techLoading}
              emptyMessage="No techniques detected for this time range"
            />
          </CardContent>
        </Card>
      )}

      {/* Charts Row - Improved */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Techniques Bar Chart */}
        <Card>
          <CardHeader
            title="Top 10 Techniques"
            subtitle="Most frequently observed attack techniques"
            icon={<Target className="w-5 h-5" />}
          />
          <CardContent>
            {summaryLoading ? (
              <div className="h-80 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart 
                    data={summary?.techniques?.slice(0, 10) || []} 
                    layout="vertical"
                    margin={{ left: 10, right: 20, top: 10, bottom: 10 }}
                  >
                    <XAxis 
                      type="number" 
                      stroke="#555" 
                      tick={{ fill: '#aaa', fontSize: 11 }}
                      tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      stroke="#555"
                      tick={{ fill: '#ccc', fontSize: 11 }}
                      width={150}
                      tickFormatter={(v) => (v.length > 20 ? v.slice(0, 18) + '...' : v)}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(26, 26, 37, 0.98)',
                        border: '1px solid rgba(255,255,255,0.2)',
                        borderRadius: '12px',
                        padding: '12px',
                      }}
                      labelStyle={{ color: '#fff', fontWeight: 'bold', marginBottom: '4px' }}
                      formatter={(value: number, _name: string, props: any) => [
                        <div key="v" className="font-mono text-lg">{value.toLocaleString()} events</div>,
                        props.payload.tactic
                      ]}
                    />
                    <Bar dataKey="count" radius={[0, 6, 6, 0]}>
                      {(summary?.techniques?.slice(0, 10) || []).map((tech: Technique, i: number) => (
                        <Cell key={i} fill={TACTIC_COLORS[tech.tactic] || '#39ff14'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Tactics Distribution - Improved */}
        <Card>
          <CardHeader
            title="Tactics Distribution"
            subtitle="Events by attack phase in the kill chain"
            icon={<Shield className="w-5 h-5" />}
          />
          <CardContent>
            {summaryLoading ? (
              <div className="h-80 flex items-center justify-center">
                <LoadingSpinner />
              </div>
            ) : (
              <div className="h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart 
                    data={summary?.tactics?.filter((t: TacticSummary) => t.total > 0) || []}
                    margin={{ left: 10, right: 20, top: 10, bottom: 80 }}
                  >
                    <XAxis
                      dataKey="tactic"
                      stroke="#555"
                      tick={{ fill: '#aaa', fontSize: 10 }}
                      interval={0}
                      angle={-45}
                      textAnchor="end"
                      height={80}
                      tickFormatter={(v) => (v.length > 14 ? v.slice(0, 12) + '...' : v)}
                    />
                    <YAxis 
                      stroke="#555" 
                      tick={{ fill: '#aaa', fontSize: 11 }}
                      tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(26, 26, 37, 0.98)',
                        border: '1px solid rgba(255,255,255,0.2)',
                        borderRadius: '12px',
                        padding: '12px',
                      }}
                      labelStyle={{ color: '#fff', fontWeight: 'bold' }}
                      formatter={(value: number) => [
                        <span key="v" className="font-mono text-lg">{value.toLocaleString()}</span>,
                        'Events'
                      ]}
                    />
                    <Bar dataKey="total" radius={[6, 6, 0, 0]}>
                      {(summary?.tactics || []).map((t: TacticSummary, i: number) => (
                        <Cell key={i} fill={TACTIC_COLORS[t.tactic] || '#39ff14'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Honeypot Coverage */}
      <Card>
        <CardHeader
          title="Honeypot Detection Coverage"
          subtitle="MITRE ATT&CK techniques detectable by each honeypot type"
          icon={<Info className="w-5 h-5" />}
        />
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {Object.entries(HONEYPOT_ICONS).map(([honeypot, icon]) => {
              const honeypotTechniques = {
                cowrie: ['T1110', 'T1078', 'T1059', 'T1082', 'T1083', 'T1018', 'T1005', 'T1021', 'T1048'],
                galah: ['T1190', 'T1595', 'T1592', 'T1071', 'T1505'],
                dionaea: ['T1190', 'T1133', 'T1571', 'T1203'],
                heralding: ['T1110', 'T1078', 'T1133', 'T1589'],
                rdpy: ['T1110', 'T1021', 'T1078'],
                firewall: ['T1046', 'T1595', 'T1571'],
              };
              
              const techCount = honeypotTechniques[honeypot as keyof typeof honeypotTechniques]?.length || 0;
              
              return (
                <div 
                  key={honeypot}
                  className="bg-bg-secondary rounded-xl p-5 text-center hover:bg-bg-hover transition-colors border border-bg-hover"
                >
                  <div className="text-4xl mb-3">{icon}</div>
                  <div className="text-sm font-semibold text-white capitalize mb-1">{honeypot}</div>
                  <div className="text-lg font-bold text-neon-green">
                    {techCount} techniques
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Tactics Legend - Improved */}
      <Card>
        <CardHeader title="MITRE ATT&CK Tactics Legend" subtitle="Click to filter the matrix by tactic" />
        <CardContent>
          <div className="flex flex-wrap gap-3">
            {TACTICS_ORDER.map((tactic) => {
              const isActive = selectedTactic === tactic;
              const tacticData = summary?.tactics?.find((t: TacticSummary) => t.tactic === tactic);
              const hasData = tacticData?.total > 0;
              
              return (
                <button
                  key={tactic}
                  onClick={() => setSelectedTactic(isActive ? null : tactic)}
                  disabled={!hasData}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all border ${
                    isActive 
                      ? 'ring-2 ring-white bg-bg-hover' 
                      : hasData 
                        ? 'hover:bg-bg-hover border-transparent' 
                        : 'opacity-40 cursor-not-allowed border-transparent'
                  }`}
                  style={{ borderColor: isActive ? TACTIC_COLORS[tactic] : undefined }}
                >
                  <div 
                    className="w-4 h-4 rounded-full" 
                    style={{ backgroundColor: TACTIC_COLORS[tactic] }} 
                  />
                  <span className="text-sm text-text-primary">{tactic}</span>
                  {hasData && (
                    <span className="text-xs text-text-muted bg-bg-secondary px-2 py-0.5 rounded-full">
                      {tacticData?.total?.toLocaleString()}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
