import { ReactNode } from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

interface StatsCardProps {
  title: string;
  value: string | number;
  icon?: ReactNode;
  trend?: number;
  trendLabel?: string;
  color?: 'green' | 'blue' | 'orange' | 'purple' | 'red' | 'yellow';
  loading?: boolean;
}

export default function StatsCard({
  title,
  value,
  icon,
  trend,
  trendLabel,
  color = 'blue',
  loading = false,
}: StatsCardProps) {
  const colorClasses = {
    green: 'text-neon-green border-neon-green/30',
    blue: 'text-neon-blue border-neon-blue/30',
    orange: 'text-neon-orange border-neon-orange/30',
    purple: 'text-neon-purple border-neon-purple/30',
    red: 'text-neon-red border-neon-red/30',
    yellow: 'text-neon-yellow border-neon-yellow/30',
  };

  const bgGlow = {
    green: 'shadow-neon-green',
    blue: 'shadow-neon-blue',
    orange: 'shadow-neon-orange',
    purple: 'shadow-neon-purple',
    red: 'shadow-neon-red',
    yellow: 'shadow-[0_0_20px_rgba(255,255,0,0.3)]',
  };

  if (loading) {
    return (
      <div className="bg-bg-card rounded-xl border border-bg-hover p-4 animate-pulse">
        <div className="h-4 bg-bg-hover rounded w-1/2 mb-3" />
        <div className="h-8 bg-bg-hover rounded w-3/4" />
      </div>
    );
  }

  return (
    <div
      className={`bg-bg-card rounded-xl border ${colorClasses[color]} p-4 hover:${bgGlow[color]} transition-shadow duration-300`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-text-secondary">{title}</span>
        {icon && <div className={colorClasses[color]}>{icon}</div>}
      </div>

      <div className="flex items-end justify-between">
        <span className={`text-2xl font-display font-bold ${colorClasses[color]}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </span>

        {trend !== undefined && (
          <div
            className={`flex items-center text-sm ${
              trend >= 0 ? 'text-neon-green' : 'text-neon-red'
            }`}
          >
            {trend >= 0 ? (
              <TrendingUp className="w-4 h-4 mr-1" />
            ) : (
              <TrendingDown className="w-4 h-4 mr-1" />
            )}
            <span>
              {Math.abs(trend)}%{trendLabel && ` ${trendLabel}`}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

