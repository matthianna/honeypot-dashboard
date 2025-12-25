import { ReactNode } from 'react';

interface CardProps {
  children: ReactNode;
  className?: string;
  hover?: boolean;
  neonColor?: 'green' | 'blue' | 'orange' | 'purple' | 'red' | 'yellow';
}

export default function Card({ children, className = '', hover = false, neonColor }: CardProps) {
  const neonBorderClasses = {
    green: 'border-neon-green/30 hover:border-neon-green/50',
    blue: 'border-neon-blue/30 hover:border-neon-blue/50',
    orange: 'border-neon-orange/30 hover:border-neon-orange/50',
    purple: 'border-neon-purple/30 hover:border-neon-purple/50',
    red: 'border-neon-red/30 hover:border-neon-red/50',
    yellow: 'border-neon-yellow/30 hover:border-neon-yellow/50',
  };

  return (
    <div
      className={`
        bg-bg-card rounded-xl border
        ${neonColor ? neonBorderClasses[neonColor] : 'border-bg-hover'}
        ${hover ? 'card-hover' : ''}
        ${className}
      `}
    >
      {children}
    </div>
  );
}

interface CardHeaderProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  icon?: ReactNode;
}

export function CardHeader({ title, subtitle, action, icon }: CardHeaderProps) {
  return (
    <div className="flex items-center justify-between p-4 border-b border-bg-hover">
      <div className="flex items-center space-x-3">
        {icon && <div className="text-neon-blue">{icon}</div>}
        <div>
          <h3 className="font-semibold text-text-primary">{title}</h3>
          {subtitle && <p className="text-sm text-text-secondary">{subtitle}</p>}
        </div>
      </div>
      {action && <div>{action}</div>}
    </div>
  );
}

interface CardContentProps {
  children: ReactNode;
  className?: string;
}

export function CardContent({ children, className = '' }: CardContentProps) {
  return <div className={`p-4 ${className}`}>{children}</div>;
}

