import { useState, useRef, useEffect } from 'react';
import { Calendar, Clock, ChevronDown } from 'lucide-react';
import type { TimeRange } from '../../types';

interface DateRangePickerProps {
  value: TimeRange;
  onChange: (value: TimeRange) => void;
  showTimezone?: boolean;
}

const PRESETS: { value: TimeRange; label: string; description: string }[] = [
  { value: '1h', label: '1 Hour', description: 'Last 60 minutes' },
  { value: '24h', label: '24 Hours', description: 'Last day' },
  { value: '7d', label: '7 Days', description: 'Last week' },
  { value: '30d', label: '30 Days', description: 'Last month' },
];

export default function DateRangePicker({
  value,
  onChange,
  showTimezone = true,
}: DateRangePickerProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const currentPreset = PRESETS.find((p) => p.value === value);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Trigger Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-4 py-2 bg-bg-card border border-bg-hover rounded-lg hover:border-neon-green/50 transition-colors"
      >
        <Calendar className="w-4 h-4 text-neon-green" />
        <span className="text-sm font-medium text-text-primary">
          {currentPreset?.label || value}
        </span>
        <ChevronDown className={`w-4 h-4 text-text-secondary transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {/* Dropdown */}
      {isOpen && (
        <div className="absolute top-full left-0 mt-2 w-64 bg-bg-card border border-bg-hover rounded-lg shadow-xl z-50 overflow-hidden">
          {/* Presets */}
          <div className="p-2">
            <div className="text-xs font-medium text-text-muted uppercase tracking-wider px-2 py-1">
              Quick Select
            </div>
            {PRESETS.map((preset) => (
              <button
                key={preset.value}
                onClick={() => {
                  onChange(preset.value);
                  setIsOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-sm transition-colors ${
                  value === preset.value
                    ? 'bg-neon-green/20 text-neon-green'
                    : 'text-text-primary hover:bg-bg-hover'
                }`}
              >
                <span className="font-medium">{preset.label}</span>
                <span className="text-text-muted text-xs">{preset.description}</span>
              </button>
            ))}
          </div>

          {/* Timezone Info */}
          {showTimezone && (
            <div className="border-t border-bg-hover p-3">
              <div className="flex items-center gap-2 text-text-muted text-xs">
                <Clock className="w-3 h-3" />
                <span>Timezone: {timezone}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

