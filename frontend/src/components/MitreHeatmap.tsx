import { useCallback } from 'react';
import { Shield, ExternalLink } from 'lucide-react';
import Card, { CardHeader, CardContent } from './Card';
import LoadingSpinner from './LoadingSpinner';
import { useApiWithRefresh } from '../hooks/useApi';
import api from '../services/api';
import type { TimeRange } from '../types';

interface MitreHeatmapProps {
  timeRange: TimeRange;
}

const TACTIC_COLORS: Record<string, string> = {
  'Reconnaissance': '#ff6600',
  'Initial Access': '#ff3366',
  'Credential Access': '#bf00ff',
  'Execution': '#00d4ff',
  'Discovery': '#39ff14',
  'Lateral Movement': '#ffff00',
  'Collection': '#ff9900',
  'Command and Control': '#9933ff',
  'Exfiltration': '#ff0066',
};

export default function MitreHeatmap({ timeRange }: MitreHeatmapProps) {
  const { data, loading } = useApiWithRefresh(
    useCallback(() => api.getMitreCoverage(timeRange), [timeRange]),
    [timeRange],
    60000
  );

  if (loading) {
    return (
      <Card>
        <CardHeader 
          title="MITRE ATT&CK Coverage" 
          subtitle="Detected attack techniques mapped to MITRE framework"
          icon={<Shield className="w-5 h-5" />} 
        />
        <CardContent>
          <div className="h-64 flex items-center justify-center">
            <LoadingSpinner />
          </div>
        </CardContent>
      </Card>
    );
  }

  const maxCount = Math.max(
    ...((data?.tactics || []).flatMap(t => t.techniques.map(tech => tech.count))),
    1
  );

  const getIntensity = (count: number) => {
    if (count === 0) return 0;
    return Math.min(1, Math.max(0.2, count / maxCount));
  };

  return (
    <Card>
      <CardHeader 
        title="MITRE ATT&CK Coverage" 
        subtitle={`${data?.summary?.techniques_detected || 0} techniques detected | ${(data?.summary?.total_technique_events || 0).toLocaleString()} total events`}
        icon={<Shield className="w-5 h-5" />}
        action={
          <a 
            href="https://attack.mitre.org/" 
            target="_blank" 
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs text-text-secondary hover:text-neon-blue transition-colors"
          >
            MITRE ATT&CK <ExternalLink className="w-3 h-3" />
          </a>
        }
      />
      <CardContent>
        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
          {data?.summary?.top_techniques?.slice(0, 5).map((tech) => (
            <div 
              key={tech.id} 
              className="bg-bg-secondary rounded-lg p-3 border border-bg-hover"
            >
              <div className="text-xs font-mono text-neon-blue mb-1">{tech.id}</div>
              <div className="text-sm text-text-primary truncate" title={tech.name}>
                {tech.name}
              </div>
              <div className="text-lg font-display font-bold text-neon-green mt-1">
                {tech.count.toLocaleString()}
              </div>
            </div>
          ))}
        </div>

        {/* Tactic Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {data?.tactics?.map((tactic) => (
            <div 
              key={tactic.tactic}
              className="bg-bg-secondary rounded-lg p-4 border border-bg-hover"
            >
              <div 
                className="text-sm font-semibold mb-3 pb-2 border-b border-bg-hover"
                style={{ color: TACTIC_COLORS[tactic.tactic] || '#888888' }}
              >
                {tactic.tactic}
              </div>
              <div className="space-y-2">
                {tactic.techniques.map((tech) => (
                  <div 
                    key={tech.id}
                    className="flex items-center justify-between p-2 rounded"
                    style={{
                      backgroundColor: tech.detected 
                        ? `rgba(57, 255, 20, ${getIntensity(tech.count) * 0.3})` 
                        : 'rgba(255, 255, 255, 0.02)',
                      borderLeft: tech.detected 
                        ? `3px solid rgba(57, 255, 20, ${getIntensity(tech.count)})` 
                        : '3px solid transparent',
                    }}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-neon-blue">{tech.id}</span>
                        {tech.detected && (
                          <span className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
                        )}
                      </div>
                      <div 
                        className="text-sm text-text-primary truncate" 
                        title={tech.description}
                      >
                        {tech.name}
                      </div>
                    </div>
                    <div className="text-right ml-2">
                      {tech.detected ? (
                        <span className="font-mono text-sm font-bold text-neon-green">
                          {tech.count.toLocaleString()}
                        </span>
                      ) : (
                        <span className="text-xs text-text-muted">—</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Legend */}
        <div className="mt-6 flex items-center justify-center gap-6 text-xs text-text-secondary">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded bg-neon-green/30 border-l-2 border-neon-green" />
            <span>Detected</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded bg-white/5" />
            <span>Not Detected</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
            <span>Active</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

