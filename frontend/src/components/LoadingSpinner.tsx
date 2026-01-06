interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  variant?: 'default' | 'honeypot' | 'hexagon';
}

export default function LoadingSpinner({ 
  size = 'md', 
  className = '',
  variant = 'default'
}: LoadingSpinnerProps) {
  const sizeClasses = {
    sm: 'w-5 h-5',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  };

  const borderSizes = {
    sm: 'border-2',
    md: 'border-2',
    lg: 'border-3',
  };

  if (variant === 'hexagon') {
    return (
      <div className={`flex items-center justify-center ${className}`}>
        <div className={`${sizeClasses[size]} relative`}>
          {/* Outer spinning ring */}
          <svg
            className="animate-spin"
            viewBox="0 0 50 50"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* Hexagon outline */}
            <path
              d="M25 2L45.5 14.5V37.5L25 50L4.5 37.5V14.5L25 2Z"
              stroke="url(#spinGradient)"
              strokeWidth="3"
              strokeLinecap="round"
              strokeDasharray="80 40"
            />
            <defs>
              <linearGradient id="spinGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#39ff14" />
                <stop offset="50%" stopColor="#00d4ff" />
                <stop offset="100%" stopColor="#39ff14" stopOpacity="0" />
              </linearGradient>
            </defs>
          </svg>
          {/* Center dot */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-2 h-2 rounded-full bg-neon-green animate-pulse" />
          </div>
        </div>
      </div>
    );
  }

  if (variant === 'honeypot') {
    return (
      <div className={`flex items-center justify-center ${className}`}>
        <div className={`${sizeClasses[size]} relative`}>
          {/* Multiple concentric rings */}
          <div className="absolute inset-0 rounded-full border-2 border-neon-green/20 animate-ping" />
          <div className="absolute inset-1 rounded-full border-2 border-neon-blue/30 animate-pulse" />
          <div 
            className={`${sizeClasses[size]} ${borderSizes[size]} rounded-full border-transparent border-t-neon-green border-r-neon-blue animate-spin`}
            style={{ animationDuration: '0.8s' }}
          />
          {/* Inner glow */}
          <div className="absolute inset-2 rounded-full bg-gradient-to-br from-neon-green/10 to-neon-blue/10" />
        </div>
      </div>
    );
  }

  // Default spinner
  return (
    <div className={`flex items-center justify-center ${className}`}>
      <div
        className={`${sizeClasses[size]} ${borderSizes[size]} rounded-full border-bg-card border-t-neon-blue animate-spin`}
      />
    </div>
  );
}

// Full page loading overlay
export function LoadingOverlay({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="fixed inset-0 bg-bg-primary/80 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="text-center">
        <LoadingSpinner size="lg" variant="honeypot" className="mb-4" />
        <p className="text-text-secondary animate-pulse">{message}</p>
      </div>
    </div>
  );
}

// Inline loading indicator
export function InlineLoader({ text = 'Loading' }: { text?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-text-muted">
      <LoadingSpinner size="sm" />
      <span>{text}</span>
    </span>
  );
}
