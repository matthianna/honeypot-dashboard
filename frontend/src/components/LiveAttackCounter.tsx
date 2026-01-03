import { useState, useEffect, useRef } from 'react';
import { Zap, TrendingUp, TrendingDown, Minus, Activity } from 'lucide-react';
import api from '../services/api';

interface VelocityData {
  stats: {
    avg_per_minute: number;
    max_per_minute: number;
    current_per_minute: number;
  };
  velocity: Array<{ timestamp: string; count: number }>;
}

export default function LiveAttackCounter() {
  const [velocityData, setVelocityData] = useState<VelocityData | null>(null);
  const [displayCount, setDisplayCount] = useState(0);
  const [isAnimating, setIsAnimating] = useState(false);
  const [trend, setTrend] = useState<'increasing' | 'decreasing' | 'stable'>('stable');
  const [trendPercentage, setTrendPercentage] = useState(0);
  const prevCountRef = useRef(0);

  useEffect(() => {
    const fetchVelocity = async () => {
      try {
        const data = await api.getAttackVelocity();
        setVelocityData(data);
        
        // Calculate total from velocity data
        const total = data.velocity.reduce((sum, v) => sum + v.count, 0);
        
        // Calculate trend
        if (data.velocity.length >= 2) {
          const recent = data.velocity.slice(-3).reduce((s, v) => s + v.count, 0) / 3;
          const older = data.velocity.slice(0, 3).reduce((s, v) => s + v.count, 0) / 3;
          const pct = older > 0 ? ((recent - older) / older) * 100 : 0;
          setTrendPercentage(Math.abs(pct));
          setTrend(pct > 10 ? 'increasing' : pct < -10 ? 'decreasing' : 'stable');
        }
        
        // Animate counter
        if (total !== prevCountRef.current) {
          animateCounter(prevCountRef.current, total);
          prevCountRef.current = total;
          
          // Trigger pulse animation
          setIsAnimating(true);
          setTimeout(() => setIsAnimating(false), 500);
        }
      } catch (err) {
        console.error('Failed to fetch velocity:', err);
      }
    };

    fetchVelocity();
    const interval = setInterval(fetchVelocity, 5000); // Update every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const animateCounter = (from: number, to: number) => {
    const duration = 1000;
    const steps = 30;
    const increment = (to - from) / steps;
    let current = from;
    let step = 0;

    const timer = setInterval(() => {
      step++;
      current += increment;
      setDisplayCount(Math.round(current));
      
      if (step >= steps) {
        clearInterval(timer);
        setDisplayCount(to);
      }
    }, duration / steps);
  };

  const getTrendIcon = () => {
    switch (trend) {
      case 'increasing':
        return <TrendingUp className="w-4 h-4 text-red-400" />;
      case 'decreasing':
        return <TrendingDown className="w-4 h-4 text-green-400" />;
      default:
        return <Minus className="w-4 h-4 text-yellow-400" />;
    }
  };

  const getTrendColor = () => {
    switch (trend) {
      case 'increasing':
        return 'text-red-400';
      case 'decreasing':
        return 'text-green-400';
      default:
        return 'text-yellow-400';
    }
  };

  return (
    <div className="bg-gradient-to-br from-bg-secondary to-bg-card rounded-xl border border-bg-hover p-6 relative overflow-hidden">
      {/* Animated background pulse */}
      <div 
        className={`absolute inset-0 bg-neon-green/5 transition-opacity duration-500 ${isAnimating ? 'opacity-100' : 'opacity-0'}`}
      />
      
      {/* Header */}
      <div className="flex items-center justify-between mb-4 relative z-10">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-neon-green/20 rounded-lg">
            <Zap className="w-5 h-5 text-neon-green" />
          </div>
          <span className="text-text-secondary font-medium">Live Attack Rate</span>
        </div>
        <div className="flex items-center gap-1">
          <Activity className={`w-4 h-4 ${isAnimating ? 'text-neon-green animate-pulse' : 'text-text-muted'}`} />
        </div>
      </div>

      {/* Main Counter */}
      <div className="relative z-10">
        <div className="flex items-baseline gap-2">
          <span className="text-5xl font-display font-bold text-neon-green tabular-nums">
            {displayCount.toLocaleString()}
          </span>
          <span className="text-text-muted text-sm">attacks/hour</span>
        </div>

        {/* Current rate */}
        <div className="mt-2 flex items-center gap-4">
          <div className="flex items-center gap-1">
            <span className="text-2xl font-display font-bold text-neon-blue">
              {velocityData?.stats.current_per_minute.toFixed(1) || '0'}
            </span>
            <span className="text-text-muted text-xs">/min now</span>
          </div>
          
          {/* Trend indicator */}
          <div className={`flex items-center gap-1 ${getTrendColor()}`}>
            {getTrendIcon()}
            <span className="text-sm font-medium">
              {trendPercentage.toFixed(1)}%
            </span>
          </div>
        </div>

        {/* Mini stats */}
        <div className="mt-4 grid grid-cols-2 gap-4">
          <div className="bg-bg-primary/50 rounded-lg p-3">
            <div className="text-xs text-text-muted mb-1">Max Rate</div>
            <div className="text-lg font-display font-bold text-text-primary">
              {velocityData?.stats.max_per_minute.toFixed(1) || 0}/min
            </div>
          </div>
          <div className="bg-bg-primary/50 rounded-lg p-3">
            <div className="text-xs text-text-muted mb-1">Avg Rate</div>
            <div className="text-lg font-display font-bold text-text-primary">
              {velocityData?.stats.avg_per_minute.toFixed(1) || 0}/min
            </div>
          </div>
        </div>
      </div>

      {/* Animated bar at bottom */}
      <div className="absolute bottom-0 left-0 right-0 h-1 bg-bg-hover overflow-hidden">
        <div 
          className="h-full bg-gradient-to-r from-neon-green via-neon-blue to-neon-green animate-pulse"
          style={{ 
            width: `${Math.min((velocityData?.stats.current_per_minute || 0) / (velocityData?.stats.avg_per_minute || 1) * 50, 100)}%`,
            transition: 'width 1s ease-out'
          }}
        />
      </div>
    </div>
  );
}

