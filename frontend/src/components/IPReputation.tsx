import { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, ExternalLink, Loader2, Globe, Clock, Hash } from 'lucide-react';

interface ReputationData {
  ip: string;
  score: number; // 0-100, higher is worse
  category: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  reports: number;
  lastSeen?: string;
  country?: string;
  isp?: string;
  tags?: string[];
}

interface IPReputationProps {
  ip: string;
  compact?: boolean;
  showDetails?: boolean;
}

// Simple local scoring based on honeypot data
async function getLocalReputation(ip: string): Promise<ReputationData> {
  // In a real implementation, this would call the backend
  // For now, we'll generate mock data based on the IP
  const hash = ip.split('.').reduce((acc, oct) => acc + parseInt(oct), 0);
  const score = (hash * 7) % 100;
  
  let category: ReputationData['category'] = 'unknown';
  if (score < 25) category = 'clean';
  else if (score < 50) category = 'suspicious';
  else if (score < 75) category = 'suspicious';
  else category = 'malicious';

  return {
    ip,
    score,
    category,
    reports: Math.floor(hash / 10),
    lastSeen: new Date().toISOString(),
    tags: score > 50 ? ['scanner', 'brute-force'] : [],
  };
}

export default function IPReputation({ ip, compact = false, showDetails = true }: IPReputationProps) {
  const [data, setData] = useState<ReputationData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchReputation = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await getLocalReputation(ip);
        setData(result);
      } catch (err) {
        setError('Failed to fetch reputation');
      } finally {
        setLoading(false);
      }
    };

    fetchReputation();
  }, [ip]);

  if (loading) {
    return (
      <div className={`flex items-center gap-2 ${compact ? '' : 'p-4'}`}>
        <Loader2 className="w-4 h-4 animate-spin text-text-muted" />
        <span className="text-sm text-text-muted">Checking reputation...</span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className={`flex items-center gap-2 text-text-muted ${compact ? '' : 'p-4'}`}>
        <AlertTriangle className="w-4 h-4" />
        <span className="text-sm">{error || 'Unknown'}</span>
      </div>
    );
  }

  const getScoreColor = () => {
    if (data.score < 25) return 'text-neon-green';
    if (data.score < 50) return 'text-neon-orange';
    if (data.score < 75) return 'text-neon-orange';
    return 'text-neon-red';
  };

  const getCategoryBadge = () => {
    const styles = {
      clean: 'bg-neon-green/20 text-neon-green border-neon-green/30',
      suspicious: 'bg-neon-orange/20 text-neon-orange border-neon-orange/30',
      malicious: 'bg-neon-red/20 text-neon-red border-neon-red/30',
      unknown: 'bg-text-muted/20 text-text-muted border-text-muted/30',
    };
    return styles[data.category];
  };

  const getCategoryIcon = () => {
    switch (data.category) {
      case 'clean':
        return <CheckCircle className="w-4 h-4 text-neon-green" />;
      case 'suspicious':
        return <AlertTriangle className="w-4 h-4 text-neon-orange" />;
      case 'malicious':
        return <Shield className="w-4 h-4 text-neon-red" />;
      default:
        return <Globe className="w-4 h-4 text-text-muted" />;
    }
  };

  if (compact) {
    return (
      <div className="flex items-center gap-2">
        {getCategoryIcon()}
        <span className={`text-sm font-medium ${getScoreColor()}`}>
          {data.score}
        </span>
        <span className={`text-xs px-1.5 py-0.5 rounded border ${getCategoryBadge()}`}>
          {data.category}
        </span>
      </div>
    );
  }

  return (
    <div className="bg-bg-card rounded-xl border border-bg-hover p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
            data.category === 'malicious' ? 'bg-neon-red/20' :
            data.category === 'suspicious' ? 'bg-neon-orange/20' :
            data.category === 'clean' ? 'bg-neon-green/20' :
            'bg-bg-hover'
          }`}>
            {getCategoryIcon()}
          </div>
          <div>
            <h3 className="font-mono text-white font-medium">{ip}</h3>
            <div className={`text-xs px-2 py-0.5 rounded border inline-block ${getCategoryBadge()}`}>
              {data.category.charAt(0).toUpperCase() + data.category.slice(1)}
            </div>
          </div>
        </div>
        
        {/* Score gauge */}
        <div className="text-right">
          <div className={`text-3xl font-bold ${getScoreColor()}`}>
            {data.score}
          </div>
          <div className="text-xs text-text-muted">Threat Score</div>
        </div>
      </div>

      {/* Score bar */}
      <div className="mb-4">
        <div className="h-2 bg-bg-hover rounded-full overflow-hidden">
          <div 
            className={`h-full transition-all duration-500 ${
              data.score < 25 ? 'bg-neon-green' :
              data.score < 50 ? 'bg-neon-orange' :
              data.score < 75 ? 'bg-neon-orange' :
              'bg-neon-red'
            }`}
            style={{ width: `${data.score}%` }}
          />
        </div>
        <div className="flex justify-between text-xs text-text-muted mt-1">
          <span>Low Risk</span>
          <span>High Risk</span>
        </div>
      </div>

      {showDetails && (
        <>
          {/* Details */}
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div className="flex items-center gap-2 text-sm">
              <Hash className="w-4 h-4 text-text-muted" />
              <span className="text-text-muted">Reports:</span>
              <span className="text-white">{data.reports}</span>
            </div>
            {data.lastSeen && (
              <div className="flex items-center gap-2 text-sm">
                <Clock className="w-4 h-4 text-text-muted" />
                <span className="text-text-muted">Last seen:</span>
                <span className="text-white">
                  {new Date(data.lastSeen).toLocaleDateString()}
                </span>
              </div>
            )}
          </div>

          {/* Tags */}
          {data.tags && data.tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {data.tags.map((tag, i) => (
                <span 
                  key={i}
                  className="px-2 py-1 bg-bg-hover rounded text-xs text-text-secondary"
                >
                  {tag}
                </span>
              ))}
            </div>
          )}
        </>
      )}

      {/* External lookup link */}
      <div className="mt-4 pt-4 border-t border-bg-hover">
        <a
          href={`https://www.abuseipdb.com/check/${ip}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-neon-blue hover:text-neon-green transition-colors flex items-center gap-1"
        >
          <ExternalLink className="w-4 h-4" />
          Check on AbuseIPDB
        </a>
      </div>
    </div>
  );
}

// Simple badge for inline use
export function ReputationBadge({ ip }: { ip: string }) {
  return <IPReputation ip={ip} compact showDetails={false} />;
}




