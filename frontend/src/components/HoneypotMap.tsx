import { useMemo } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { COUNTRY_COORDS, normalizeCountryName, getHeatColor } from '../constants/geo';

interface GeoData {
  country: string;
  count: number;
  unique_ips?: number;
}

interface HoneypotMapProps {
  data: GeoData[];
  title?: string;
  height?: string;
  accentColor?: string;
  loading?: boolean;
}

export default function HoneypotMap({
  data,
  title = 'Attack Origins',
  height = '400px',
  accentColor = '#39ff14',
  loading = false,
}: HoneypotMapProps) {
  const markers = useMemo(() => {
    if (!data || data.length === 0) return [];
    
    // Normalize country names and filter to those with coordinates
    const countriesWithCoords = data
      .map((item) => ({
        ...item,
        normalizedCountry: normalizeCountryName(item.country),
      }))
      .filter((item) => COUNTRY_COORDS[item.normalizedCountry]);
    
    const maxCount = Math.max(...countriesWithCoords.map((c) => c.count), 1);
    
    return countriesWithCoords.map((item) => {
      const logIntensity = Math.log10(item.count + 1) / Math.log10(maxCount + 1);
      const heatColor = getHeatColor(logIntensity);
      
      return {
        country: item.country, // Keep original name for display
        count: item.count,
        unique_ips: item.unique_ips || 0,
        coords: COUNTRY_COORDS[item.normalizedCountry],
        radius: Math.max(6, Math.min(35, Math.log10(item.count + 1) * 12)),
        color: heatColor,
        intensity: logIntensity,
      };
    });
  }, [data]);

  const totalEvents = useMemo(() => data.reduce((sum, d) => sum + d.count, 0), [data]);

  if (loading) {
    return (
      <div className="rounded-xl overflow-hidden border border-bg-hover" style={{ height }}>
        <div className="h-full flex items-center justify-center bg-bg-secondary">
          <div className="flex flex-col items-center gap-2">
            <div className="w-8 h-8 border-2 border-neon-green border-t-transparent rounded-full animate-spin" />
            <span className="text-sm text-text-muted">Loading map...</span>
          </div>
        </div>
      </div>
    );
  }

  if (markers.length === 0) {
    return (
      <div className="rounded-xl overflow-hidden border border-bg-hover" style={{ height }}>
        <div className="h-full flex items-center justify-center bg-bg-secondary">
          <span className="text-text-muted">No geographic data available</span>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl overflow-hidden border border-bg-hover relative" style={{ height }}>
      <MapContainer
        center={[20, 0]}
        zoom={2}
        minZoom={1}
        maxZoom={6}
        style={{ width: '100%', height: '100%', background: '#0a0a12' }}
        attributionControl={false}
      >
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png"
          attribution='&copy; CARTO'
        />
        {markers.map((marker) => (
          <CircleMarker
            key={marker.country}
            center={marker.coords}
            radius={marker.radius}
            pathOptions={{
              color: marker.color,
              fillColor: marker.color,
              fillOpacity: 0.7,
              weight: 2,
            }}
          >
            <Popup>
              <div className="text-center p-1" style={{ color: '#1a1a25', background: 'white' }}>
                <div className="font-bold text-lg" style={{ color: '#111' }}>{marker.country}</div>
                <div className="font-medium" style={{ color: '#333' }}>
                  {marker.count.toLocaleString()} events
                </div>
                {marker.unique_ips > 0 && (
                  <div style={{ color: '#555' }}>
                    {marker.unique_ips.toLocaleString()} unique IPs
                  </div>
                )}
                <div className="text-xs mt-1" style={{ color: '#666' }}>
                  {((marker.count / totalEvents) * 100).toFixed(1)}% of total
                </div>
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 bg-bg-card/90 backdrop-blur-sm rounded-lg p-2 border border-bg-hover">
        <div className="text-xs text-text-secondary mb-1 font-medium">Attack Intensity</div>
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-text-muted">Low</span>
          <div className="flex h-2">
            {['#1a472a', '#4a7c59', '#b4cf66', '#f9dc5c', '#f4a259', '#f25c54', '#9d0208'].map((color, i) => (
              <div key={i} className="w-3 h-full" style={{ backgroundColor: color }} />
            ))}
          </div>
          <span className="text-[10px] text-text-muted">High</span>
        </div>
      </div>

      {/* Title Overlay */}
      {title && (
        <div className="absolute top-3 left-3 bg-bg-card/80 backdrop-blur-sm rounded-lg px-3 py-1.5 border border-bg-hover">
          <span className="text-sm font-medium" style={{ color: accentColor }}>{title}</span>
        </div>
      )}
    </div>
  );
}

