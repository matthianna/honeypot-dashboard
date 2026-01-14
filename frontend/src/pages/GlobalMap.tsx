import { Globe } from 'lucide-react';
import TimeRangeSelector from '../components/TimeRangeSelector';
import WorldChoroplethMap from '../components/WorldChoroplethMap';
import { useTimeRange } from '../hooks/useTimeRange';

export default function GlobalMap() {
  const { timeRange, setTimeRange } = useTimeRange('7d');

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Globe className="w-7 h-7 text-neon-orange" />
          <div>
            <h1 className="text-xl font-display font-bold text-white">Global Attack Map</h1>
            <p className="text-xs text-text-secondary">
              Honeypots only • Use scroll to zoom • Drag to pan • Click fullscreen for best view
            </p>
          </div>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Full Map */}
      <WorldChoroplethMap timeRange={timeRange} height={700} />
    </div>
  );
}
