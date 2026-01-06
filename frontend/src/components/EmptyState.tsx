import { ReactNode } from 'react';
import { Inbox, Search, AlertCircle, Database, FileX, Frown } from 'lucide-react';

type EmptyStateVariant = 'default' | 'search' | 'error' | 'no-data' | 'no-results' | 'empty';

interface EmptyStateProps {
  title?: string;
  description?: string;
  icon?: ReactNode;
  variant?: EmptyStateVariant;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

const VARIANT_DEFAULTS: Record<EmptyStateVariant, { icon: ReactNode; title: string; description: string }> = {
  default: {
    icon: <Inbox className="w-12 h-12" />,
    title: 'No data available',
    description: 'There is no data to display at this time.',
  },
  search: {
    icon: <Search className="w-12 h-12" />,
    title: 'No results found',
    description: 'Try adjusting your search or filter criteria.',
  },
  error: {
    icon: <AlertCircle className="w-12 h-12" />,
    title: 'Failed to load data',
    description: 'An error occurred while loading. Please try again.',
  },
  'no-data': {
    icon: <Database className="w-12 h-12" />,
    title: 'No data collected',
    description: 'Data will appear here once events are captured.',
  },
  'no-results': {
    icon: <FileX className="w-12 h-12" />,
    title: 'No matching results',
    description: 'No items match your current filters.',
  },
  empty: {
    icon: <Frown className="w-12 h-12" />,
    title: 'Nothing here yet',
    description: 'This section is empty.',
  },
};

const SIZE_CLASSES = {
  sm: {
    container: 'py-8',
    icon: 'w-10 h-10',
    title: 'text-sm',
    description: 'text-xs',
  },
  md: {
    container: 'py-12',
    icon: 'w-12 h-12',
    title: 'text-base',
    description: 'text-sm',
  },
  lg: {
    container: 'py-16',
    icon: 'w-16 h-16',
    title: 'text-lg',
    description: 'text-base',
  },
};

export default function EmptyState({
  title,
  description,
  icon,
  variant = 'default',
  action,
  className = '',
  size = 'md',
}: EmptyStateProps) {
  const defaults = VARIANT_DEFAULTS[variant];
  const sizeClasses = SIZE_CLASSES[size];

  const displayIcon = icon || defaults.icon;
  const displayTitle = title || defaults.title;
  const displayDescription = description || defaults.description;

  return (
    <div className={`flex flex-col items-center justify-center text-center ${sizeClasses.container} ${className}`}>
      {/* Icon */}
      <div className="text-text-muted mb-4 opacity-50">
        {displayIcon}
      </div>

      {/* Title */}
      <h3 className={`font-medium text-text-primary mb-1 ${sizeClasses.title}`}>
        {displayTitle}
      </h3>

      {/* Description */}
      <p className={`text-text-muted max-w-sm ${sizeClasses.description}`}>
        {displayDescription}
      </p>

      {/* Action button */}
      {action && (
        <button
          onClick={action.onClick}
          className="mt-4 px-4 py-2 bg-neon-green/10 text-neon-green rounded-lg hover:bg-neon-green/20 transition-colors text-sm font-medium"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}

// Inline empty state for tables and lists
export function InlineEmptyState({ message = 'No data available' }: { message?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-8 text-text-muted">
      <Inbox className="w-5 h-5 opacity-50" />
      <span className="text-sm">{message}</span>
    </div>
  );
}




