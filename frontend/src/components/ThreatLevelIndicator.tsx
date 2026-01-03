import { useState, useEffect } from 'react';
import { AlertTriangle, Shield, ShieldAlert, ShieldCheck, Activity } from 'lucide-react';
import api from '../services/api';

type ThreatLevel = 'low' | 'moderate' | 'elevated' | 'high' | 'critical';

interface ThreatData {
  level: ThreatLevel;
  score: number;
  factors: {
    name: string;
    value: number;
    impact: 'positive' | 'negative' | 'neutral';
  }[];
}

const THREAT_CONFIG: Record<ThreatLevel, {
  color: string;
  bgColor: string;
  borderColor: string;
  icon: typeof Shield;
  label: string;
  description: string;
}> = {
  low: {
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/30',
    icon: ShieldCheck,
    label: 'LOW',
    description: 'Normal activity levels',
  },
  moderate: {
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    icon: Shield,
    label: 'MODERATE',
    description: 'Slight increase in activity',
  },
  elevated: {
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
    icon: AlertTriangle,
    label: 'ELEVATED',
    description: 'Above average attack volume',
  },
  high: {
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    icon: ShieldAlert,
    label: 'HIGH',
    description: 'Significant attack activity',
  },
  critical: {
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    icon: ShieldAlert,
    label: 'CRITICAL',
    description: 'Extreme attack volume detected',
  },
};

export default function ThreatLevelIndicator() {
  const [threatData, setThreatData] = useState<ThreatData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const calculateThreatLevel = async () => {
      try {
        // Fetch multiple data points to calculate threat level
        const [velocityData, overview] = await Promise.all([
          api.getAttackVelocity(),
          api.getDashboardOverview('1h'),
        ]);

        // Calculate threat score (0-100)
        const factors: ThreatData['factors'] = [];
        let score = 0;

        const stats = velocityData.stats;
        const totalAttacks = velocityData.velocity.reduce((sum, v) => sum + v.count, 0);

        // Factor 1: Current attack rate vs average
        const rateRatio = stats.current_per_minute / (stats.avg_per_minute || 1);
        if (rateRatio > 2) {
          score += 30;
          factors.push({ name: 'Attack rate spike', value: Math.round(rateRatio * 100), impact: 'negative' });
        } else if (rateRatio > 1.5) {
          score += 20;
          factors.push({ name: 'Elevated attack rate', value: Math.round(rateRatio * 100), impact: 'negative' });
        } else if (rateRatio < 0.5) {
          factors.push({ name: 'Low attack rate', value: Math.round(rateRatio * 100), impact: 'positive' });
        }

        // Factor 2: Current rate vs max
        const maxRatio = stats.current_per_minute / (stats.max_per_minute || 1);
        if (maxRatio > 0.8) {
          score += 25;
          factors.push({ name: 'Near peak rate', value: Math.round(maxRatio * 100), impact: 'negative' });
        }

        // Factor 3: Total attacks in last hour
        if (totalAttacks > 10000) {
          score += 25;
          factors.push({ name: 'High volume (>10k/hr)', value: totalAttacks, impact: 'negative' });
        } else if (totalAttacks > 5000) {
          score += 15;
          factors.push({ name: 'Moderate volume', value: totalAttacks, impact: 'negative' });
        }

        // Factor 4: Unique attackers
        if (overview.total_unique_ips > 500) {
          score += 20;
          factors.push({ name: 'Many unique attackers', value: overview.total_unique_ips, impact: 'negative' });
        }

        // Determine threat level
        let level: ThreatLevel;
        if (score >= 80) level = 'critical';
        else if (score >= 60) level = 'high';
        else if (score >= 40) level = 'elevated';
        else if (score >= 20) level = 'moderate';
        else level = 'low';

        setThreatData({ level, score, factors });
      } catch (err) {
        console.error('Failed to calculate threat level:', err);
      } finally {
        setLoading(false);
      }
    };

    calculateThreatLevel();
    const interval = setInterval(calculateThreatLevel, 30000); // Update every 30 seconds

    return () => clearInterval(interval);
  }, []);

  if (loading || !threatData) {
    return (
      <div className="bg-bg-secondary rounded-xl border border-bg-hover p-6 animate-pulse">
        <div className="h-20 bg-bg-hover rounded-lg" />
      </div>
    );
  }

  const config = THREAT_CONFIG[threatData.level];
  const Icon = config.icon;

  return (
    <div className={`rounded-xl border ${config.borderColor} ${config.bgColor} p-6 relative overflow-hidden`}>
      {/* Animated background for high threat */}
      {(threatData.level === 'high' || threatData.level === 'critical') && (
        <div className="absolute inset-0 opacity-20">
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-500/20 to-transparent animate-pulse" />
        </div>
      )}

      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`p-3 rounded-xl ${config.bgColor}`}>
              <Icon className={`w-6 h-6 ${config.color}`} />
            </div>
            <div>
              <div className="text-xs text-text-muted uppercase tracking-wider">Threat Level</div>
              <div className={`text-2xl font-display font-bold ${config.color}`}>
                {config.label}
              </div>
            </div>
          </div>
          
          {/* Score gauge */}
          <div className="text-right">
            <div className="text-xs text-text-muted">Score</div>
            <div className={`text-3xl font-display font-bold ${config.color}`}>
              {threatData.score}
            </div>
          </div>
        </div>

        {/* Description */}
        <p className="text-text-secondary text-sm mb-4">{config.description}</p>

        {/* Score bar */}
        <div className="h-2 bg-bg-primary rounded-full overflow-hidden mb-4">
          <div 
            className={`h-full rounded-full transition-all duration-1000 ease-out`}
            style={{ 
              width: `${threatData.score}%`,
              background: `linear-gradient(to right, #22c55e, #eab308, #f97316, #ef4444)`,
            }}
          />
        </div>

        {/* Contributing factors */}
        {threatData.factors.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs text-text-muted uppercase tracking-wider">Contributing Factors</div>
            <div className="space-y-1">
              {threatData.factors.slice(0, 3).map((factor, i) => (
                <div key={i} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <Activity className={`w-3 h-3 ${
                      factor.impact === 'negative' ? 'text-red-400' :
                      factor.impact === 'positive' ? 'text-green-400' : 'text-text-muted'
                    }`} />
                    <span className="text-text-secondary">{factor.name}</span>
                  </div>
                  <span className={`font-mono ${
                    factor.impact === 'negative' ? 'text-red-400' :
                    factor.impact === 'positive' ? 'text-green-400' : 'text-text-muted'
                  }`}>
                    {typeof factor.value === 'number' && factor.value > 100 
                      ? factor.value.toLocaleString() 
                      : `${factor.value}%`}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

