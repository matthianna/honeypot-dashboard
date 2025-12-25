import { useState, useCallback } from 'react';
import type { TimeRange } from '../types';

export function useTimeRange(defaultValue: TimeRange = '24h') {
  const [timeRange, setTimeRange] = useState<TimeRange>(defaultValue);

  const handleTimeRangeChange = useCallback((newTimeRange: TimeRange) => {
    setTimeRange(newTimeRange);
  }, []);

  return {
    timeRange,
    setTimeRange: handleTimeRangeChange,
  };
}

