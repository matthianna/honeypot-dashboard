import type { TimeRange } from '../types';

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (value: TimeRange) => void;
  className?: string;
}

const timeRanges: { value: TimeRange; label: string }[] = [
  { value: '1h', label: '1H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
  { value: '30d', label: '30D' },
];

export default function TimeRangeSelector({
  value,
  onChange,
  className = '',
}: TimeRangeSelectorProps) {
  return (
    <div className={`flex bg-bg-secondary rounded-lg p-1 ${className}`}>
      {timeRanges.map((range) => (
        <button
          key={range.value}
          onClick={() => onChange(range.value)}
          className={`
            px-3 py-1.5 text-sm font-medium rounded-md transition-all duration-200
            ${
              value === range.value
                ? 'bg-bg-card text-neon-green shadow-sm'
                : 'text-text-secondary hover:text-text-primary'
            }
          `}
        >
          {range.label}
        </button>
      ))}
    </div>
  );
}

