import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

type TrendDirection = 'up' | 'down' | 'stable';

interface TrendBadgeProps {
  value: number; // Percentage change
  direction?: TrendDirection;
  showIcon?: boolean;
  showValue?: boolean;
  size?: 'sm' | 'md' | 'lg';
  invertColors?: boolean; // For metrics where "down" is good
  className?: string;
}

export default function TrendBadge({
  value,
  direction,
  showIcon = true,
  showValue = true,
  size = 'md',
  invertColors = false,
  className = '',
}: TrendBadgeProps) {
  // Auto-detect direction if not provided
  const actualDirection = direction || (value > 5 ? 'up' : value < -5 ? 'down' : 'stable');
  
  // Determine colors based on direction and inversion
  const getColors = () => {
    if (actualDirection === 'stable') {
      return {
        bg: 'bg-text-muted/10',
        text: 'text-text-muted',
        border: 'border-text-muted/20',
      };
    }
    
    const isPositive = actualDirection === 'up';
    const isGood = invertColors ? !isPositive : isPositive;
    
    // For attack metrics, "up" is bad (red), "down" is good (green)
    // For invertColors=true, we flip this
    if (isGood) {
      return {
        bg: invertColors ? 'bg-neon-green/10' : 'bg-neon-red/10',
        text: invertColors ? 'text-neon-green' : 'text-neon-red',
        border: invertColors ? 'border-neon-green/20' : 'border-neon-red/20',
      };
    } else {
      return {
        bg: invertColors ? 'bg-neon-red/10' : 'bg-neon-green/10',
        text: invertColors ? 'text-neon-red' : 'text-neon-green',
        border: invertColors ? 'border-neon-red/20' : 'border-neon-green/20',
      };
    }
  };
  
  const sizeClasses = {
    sm: 'text-xs px-1.5 py-0.5 gap-0.5',
    md: 'text-sm px-2 py-1 gap-1',
    lg: 'text-base px-3 py-1.5 gap-1.5',
  };
  
  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-4 h-4',
    lg: 'w-5 h-5',
  };
  
  const colors = getColors();
  
  const Icon = actualDirection === 'up' 
    ? TrendingUp 
    : actualDirection === 'down' 
    ? TrendingDown 
    : Minus;
  
  const displayValue = Math.abs(value).toFixed(1);

  return (
    <span
      className={`inline-flex items-center rounded-full border font-medium ${colors.bg} ${colors.text} ${colors.border} ${sizeClasses[size]} ${className}`}
    >
      {showIcon && <Icon className={iconSizes[size]} />}
      {showValue && (
        <span>
          {actualDirection !== 'stable' && (actualDirection === 'up' ? '+' : '-')}
          {displayValue}%
        </span>
      )}
    </span>
  );
}

// Trend indicator with label
export function TrendIndicator({
  value,
  label,
  invertColors = false,
  className = '',
}: {
  value: number;
  label?: string;
  invertColors?: boolean;
  className?: string;
}) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <TrendBadge value={value} invertColors={invertColors} size="sm" />
      {label && (
        <span className="text-xs text-text-muted">
          {label}
        </span>
      )}
    </div>
  );
}

// Compare value with previous period
export function CompareWithPrevious({
  current,
  previous,
  label = 'vs previous',
  invertColors = false,
}: {
  current: number;
  previous: number;
  label?: string;
  invertColors?: boolean;
}) {
  if (previous === 0) return null;
  
  const percentChange = ((current - previous) / previous) * 100;
  
  return (
    <TrendIndicator
      value={percentChange}
      label={label}
      invertColors={invertColors}
    />
  );
}

