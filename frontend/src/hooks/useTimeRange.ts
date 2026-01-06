import { useState, useCallback, useEffect } from 'react';
import type { TimeRange } from '../types';

const STORAGE_KEY = 'honeypot_timeRange';

// Valid time ranges
const VALID_TIME_RANGES: TimeRange[] = ['1h', '24h', '7d', '30d'];

function isValidTimeRange(value: string | null): value is TimeRange {
  return value !== null && VALID_TIME_RANGES.includes(value as TimeRange);
}

export function useTimeRange(defaultValue: TimeRange = '24h') {
  const [timeRange, setTimeRangeState] = useState<TimeRange>(() => {
    // Try to get from localStorage on initial render
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (isValidTimeRange(saved)) {
        return saved;
      }
    } catch {
      // localStorage not available
    }
    return defaultValue;
  });

  // Persist to localStorage when changed
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, timeRange);
    } catch {
      // localStorage not available
    }
  }, [timeRange]);

  const handleTimeRangeChange = useCallback((newTimeRange: TimeRange) => {
    setTimeRangeState(newTimeRange);
  }, []);

  return {
    timeRange,
    setTimeRange: handleTimeRangeChange,
  };
}
