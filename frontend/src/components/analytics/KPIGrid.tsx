import { ReactNode } from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface KPICardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: ReactNode;
  color?: 'green' | 'blue' | 'orange' | 'red' | 'purple' | 'yellow';
  trend?: {
    value: number;
    direction: 'up' | 'down' | 'neutral';
    label?: string;
  };
  loading?: boolean;
}

const colorClasses = {
  green: 'text-neon-green bg-neon-green/10 border-neon-green/20',
  blue: 'text-neon-blue bg-neon-blue/10 border-neon-blue/20',
  orange: 'text-neon-orange bg-neon-orange/10 border-neon-orange/20',
  red: 'text-neon-red bg-neon-red/10 border-neon-red/20',
  purple: 'text-neon-purple bg-neon-purple/10 border-neon-purple/20',
  yellow: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
};

export function KPICard({
  title,
  value,
  subtitle,
  icon,
  color = 'green',
  trend,
  loading = false,
}: KPICardProps) {
  if (loading) {
    return (
      <div className="bg-bg-card border border-bg-hover rounded-xl p-5 animate-pulse">
        <div className="h-4 bg-bg-hover rounded w-1/2 mb-3" />
        <div className="h-8 bg-bg-hover rounded w-2/3 mb-2" />
        <div className="h-3 bg-bg-hover rounded w-1/3" />
      </div>
    );
  }

  const TrendIcon = trend?.direction === 'up' ? TrendingUp : trend?.direction === 'down' ? TrendingDown : Minus;
  const trendColor = trend?.direction === 'up' ? 'text-neon-red' : trend?.direction === 'down' ? 'text-neon-green' : 'text-text-muted';

  return (
    <div className={`bg-bg-card border rounded-xl p-5 ${colorClasses[color].split(' ')[2]}`}>
      <div className="flex items-start justify-between mb-3">
        <span className="text-sm text-text-secondary font-medium">{title}</span>
        {icon && (
          <div className={`p-2 rounded-lg ${colorClasses[color]}`}>
            {icon}
          </div>
        )}
      </div>
      
      <div className={`text-3xl font-display font-bold mb-1 ${colorClasses[color].split(' ')[0]}`}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      
      <div className="flex items-center gap-2">
        {subtitle && (
          <span className="text-xs text-text-muted">{subtitle}</span>
        )}
        {trend && (
          <div className={`flex items-center gap-1 text-xs ${trendColor}`}>
            <TrendIcon className="w-3 h-3" />
            <span>{trend.value}%</span>
            {trend.label && <span className="text-text-muted">{trend.label}</span>}
          </div>
        )}
      </div>
    </div>
  );
}

interface KPIGridProps {
  children: ReactNode;
  columns?: 2 | 3 | 4 | 5 | 6;
}

export default function KPIGrid({ children, columns = 4 }: KPIGridProps) {
  const gridClasses = {
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4',
    5: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-5',
    6: 'grid-cols-2 md:grid-cols-3 lg:grid-cols-6',
  };

  return (
    <div className={`grid gap-4 ${gridClasses[columns]}`}>
      {children}
    </div>
  );
}

