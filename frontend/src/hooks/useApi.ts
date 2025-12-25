import { useState, useEffect, useCallback } from 'react';

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
}

interface UseApiResult<T> extends UseApiState<T> {
  refetch: () => Promise<void>;
}

export function useApi<T>(
  fetchFn: () => Promise<T>,
  dependencies: unknown[] = []
): UseApiResult<T> {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const fetchData = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    try {
      const data = await fetchFn();
      setState({ data, loading: false, error: null });
    } catch (error) {
      setState({ data: null, loading: false, error: error as Error });
    }
  }, [fetchFn]);

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  return {
    ...state,
    refetch: fetchData,
  };
}

// Hook for data that auto-refreshes
export function useApiWithRefresh<T>(
  fetchFn: () => Promise<T>,
  dependencies: unknown[] = [],
  refreshInterval: number = 30000 // 30 seconds default
): UseApiResult<T> {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: true,
    error: null,
  });

  const fetchData = useCallback(async () => {
    try {
      const data = await fetchFn();
      setState({ data, loading: false, error: null });
    } catch (error) {
      setState(prev => ({ ...prev, loading: false, error: error as Error }));
    }
  }, [fetchFn]);

  useEffect(() => {
    setState(prev => ({ ...prev, loading: true }));
    fetchData();

    const interval = setInterval(fetchData, refreshInterval);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, refreshInterval]);

  return {
    ...state,
    refetch: fetchData,
  };
}

