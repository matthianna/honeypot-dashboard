import { useEffect, useRef, useState, useCallback } from 'react';
import { ComposableMap, Geographies, Geography, Marker, type Geography as GeoType } from 'react-simple-maps';
import { Pause, Play, Maximize2, Minimize2, Zap, RefreshCw } from 'lucide-react';
import api from '../services/api';

// World map TopoJSON
const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Target coordinates for our internal hosts
const TARGET_COORDS: Record<string, [number, number]> = {
  '193.246.121.231': [8.5417, 47.3769], // Zurich
  '193.246.121.232': [8.5417, 47.3769],
  '193.246.121.233': [8.5417, 47.3769],
};
const DEFAULT_TARGET: [number, number] = [8.5417, 47.3769];

// Service colors by port
const PORT_COLORS: Record<number, string> = {
  22: '#39ff14',    // SSH - green
  80: '#00d4ff',    // HTTP - blue
  443: '#00d4ff',   // HTTPS - blue
  3389: '#bf00ff',  // RDP - purple
  5060: '#ff6600',  // SIP - orange
  53: '#ffff00',    // DNS - yellow
  23: '#ff3366',    // Telnet - red
  21: '#ff3366',    // FTP - red
};
const DEFAULT_COLOR = '#888888';

interface Attack {
  id: string;
  timestamp: string;
  src_ip: string;
  src_lat: number;
  src_lon: number;
  src_country: string | null | undefined;
  dst_ip: string;
  dst_port: number;
  age: number;
  opacity: number;
  pulsePhase: number;
}

type TimeRange = '1h' | '24h' | '7d' | '30d';

interface FirewallAttackMapProps {
  timeRange?: TimeRange;
}

export default function FirewallAttackMap({ timeRange = '1h' }: FirewallAttackMapProps) {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [recentList, setRecentList] = useState<Attack[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [stats, setStats] = useState({ total: 0, uniqueIps: 0, uniquePorts: 0 });
  
  const containerRef = useRef<HTMLDivElement>(null);
  const attackIdRef = useRef(0);
  const animationRef = useRef<number>();
  const seenIdsRef = useRef(new Set<string>());
  const pollIntervalRef = useRef<ReturnType<typeof setInterval>>();
  
  // Get color based on port
  const getPortColor = (port: number) => PORT_COLORS[port] || DEFAULT_COLOR;
  
  // Add a new attack
  const addAttack = useCallback((data: {
    id: string;
    timestamp: string;
    src_ip: string;
    src_lat?: number | null;
    src_lon?: number | null;
    src_country?: string | null;
    dst_ip: string;
    dst_port: number;
  }) => {
    if (!data.src_lat || !data.src_lon) return;
    
    // Skip if already seen
    if (seenIdsRef.current.has(data.id)) return;
    seenIdsRef.current.add(data.id);
    
    // Limit seen IDs
    if (seenIdsRef.current.size > 1000) {
      const arr = Array.from(seenIdsRef.current);
      seenIdsRef.current.clear();
      arr.slice(-500).forEach(id => seenIdsRef.current.add(id));
    }
    
    const attack: Attack = {
      id: `${data.id}-${attackIdRef.current++}`,
      timestamp: data.timestamp,
      src_ip: data.src_ip,
      src_lat: data.src_lat,
      src_lon: data.src_lon,
      src_country: data.src_country,
      dst_ip: data.dst_ip,
      dst_port: data.dst_port,
      age: 0,
      opacity: 1,
      pulsePhase: 0,
    };
    
    setAttacks(prev => [...prev.slice(-150), attack]);
    setRecentList(prev => [attack, ...prev.slice(0, 19)]);
  }, []);
  
  // Animation loop
  useEffect(() => {
    let lastTime = performance.now();
    
    const animate = (time: number) => {
      const delta = (time - lastTime) / 1000;
      lastTime = time;
      
      setAttacks(prev => prev
        .map(a => ({
          ...a,
          age: a.age + delta,
          opacity: Math.max(0, 1 - a.age / 10), // 10 second fade
          pulsePhase: (a.pulsePhase + delta * 2) % (Math.PI * 2),
        }))
        .filter(a => a.opacity > 0)
      );
      
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animationRef.current = requestAnimationFrame(animate);
    return () => {
      if (animationRef.current) cancelAnimationFrame(animationRef.current);
    };
  }, []);
  
  // Fetch firewall events
  const fetchEvents = useCallback(async () => {
    try {
      const response = await api.getFirewallEvents(timeRange, 50);
      const events = response.events || [];
      
      events.forEach((event: Record<string, unknown>) => {
        const srcGeo = event.source_geo as { lat?: number; lon?: number; country?: string } | undefined;
        if (srcGeo?.lat && srcGeo?.lon) {
          addAttack({
            id: String(event.id || Math.random()),
            timestamp: String(event.timestamp || ''),
            src_ip: String(event.source_ip || ''),
            src_lat: srcGeo.lat,
            src_lon: srcGeo.lon,
            src_country: srcGeo.country,
            dst_ip: String(event.dest_ip || ''),
            dst_port: Number(event.dest_port) || 0,
          });
        }
      });
      
      // Update stats
      const statsData = await api.getFirewallStats(timeRange);
      setStats({
        total: statsData.total_events || 0,
        uniqueIps: statsData.unique_ips || 0,
        uniquePorts: 0,
      });
    } catch (e) {
      console.error('Failed to fetch firewall events:', e);
    }
  }, [timeRange, addAttack]);
  
  // Start polling
  useEffect(() => {
    if (isPaused) {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = undefined;
      }
      return;
    }
    
    // Initial fetch
    fetchEvents();
    
    // Poll every 3 seconds
    pollIntervalRef.current = setInterval(fetchEvents, 3000);
    
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [isPaused, fetchEvents]);
  
  // Fullscreen toggle
  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen();
      setIsFullscreen(true);
    } else {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  };
  
  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
      });
    } catch {
      return '';
    }
  };

  return (
    <div 
      ref={containerRef}
      className={`relative bg-[#0a0a12] rounded-xl overflow-hidden ${
        isFullscreen ? 'fixed inset-0 z-50' : 'h-[500px]'
      }`}
    >
      {/* Map */}
      <div className="absolute inset-0">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{
            scale: 140,
            center: [10, 35],
          }}
          style={{ width: '100%', height: '100%' }}
        >
          <Geographies geography={GEO_URL}>
            {({ geographies }: { geographies: GeoType[] }) =>
              geographies.map((geo: GeoType) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#1a1a2e"
                  stroke="#2a2a4a"
                  strokeWidth={0.5}
                  style={{
                    default: { outline: 'none' },
                    hover: { outline: 'none', fill: '#252545' },
                    pressed: { outline: 'none' },
                  }}
                />
              ))
            }
          </Geographies>
          
          {/* Target marker (Zurich) */}
          <Marker coordinates={DEFAULT_TARGET}>
            <circle r={8} fill="#ffff00" fillOpacity={0.3} />
            <circle r={4} fill="#ffff00" />
            <circle r={12} fill="none" stroke="#ffff00" strokeWidth={1} strokeOpacity={0.5}>
              <animate attributeName="r" from="8" to="20" dur="2s" repeatCount="indefinite" />
              <animate attributeName="stroke-opacity" from="0.5" to="0" dur="2s" repeatCount="indefinite" />
            </circle>
          </Marker>
          
          {/* Attack markers */}
          {attacks.map((attack) => {
            const color = getPortColor(attack.dst_port);
            const pulseSize = 5 + Math.sin(attack.pulsePhase) * 2;
            const targetCoords = TARGET_COORDS[attack.dst_ip] || DEFAULT_TARGET;
            
            return (
              <Marker key={attack.id} coordinates={[attack.src_lon, attack.src_lat]}>
                {/* Outer pulse */}
                <circle
                  r={pulseSize + 6}
                  fill="none"
                  stroke={color}
                  strokeWidth={1}
                  opacity={attack.opacity * 0.3}
                />
                {/* Core dot */}
                <circle
                  r={pulseSize}
                  fill={color}
                  opacity={attack.opacity}
                  style={{
                    filter: `drop-shadow(0 0 ${3 + attack.pulsePhase}px ${color})`,
                  }}
                />
                {/* Connection line */}
                {attack.age < 3 && (
                  <line
                    x1={0}
                    y1={0}
                    x2={(targetCoords[0] - attack.src_lon) * 2}
                    y2={(targetCoords[1] - attack.src_lat) * 2}
                    stroke={color}
                    strokeWidth={1}
                    strokeDasharray="4 4"
                    opacity={Math.max(0, 1 - attack.age / 3) * 0.4}
                  />
                )}
              </Marker>
            );
          })}
        </ComposableMap>
      </div>
      
      {/* Stats Overlay */}
      <div className="absolute top-4 left-4 bg-black/70 backdrop-blur-md rounded-xl p-4 border border-white/10">
        <div className="flex items-center gap-2 mb-3">
          <Zap className="w-4 h-4 text-yellow-400" />
          <span className="text-xs uppercase tracking-wider text-text-muted">Firewall Live</span>
          <span className={`w-2 h-2 rounded-full ml-2 ${isPaused ? 'bg-yellow-500' : 'bg-neon-green animate-pulse'}`} />
        </div>
        <div className="grid grid-cols-2 gap-6">
          <div>
            <div className="text-2xl font-display font-bold text-yellow-400">
              {stats.total.toLocaleString()}
            </div>
            <div className="text-xs text-text-secondary">Events</div>
          </div>
          <div>
            <div className="text-2xl font-display font-bold text-neon-blue">
              {stats.uniqueIps.toLocaleString()}
            </div>
            <div className="text-xs text-text-secondary">Unique IPs</div>
          </div>
        </div>
      </div>
      
      {/* Controls */}
      <div className="absolute top-4 right-4 flex gap-2">
        <button
          onClick={fetchEvents}
          className="p-2 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-yellow-400 transition-all"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
        <button
          onClick={() => setIsPaused(!isPaused)}
          className={`p-2 rounded-lg backdrop-blur-md border transition-all ${
            isPaused 
              ? 'bg-yellow-400/20 border-yellow-400 text-yellow-400' 
              : 'bg-black/50 border-white/10 text-text-secondary hover:text-white'
          }`}
        >
          {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
        </button>
        <button
          onClick={toggleFullscreen}
          className="p-2 rounded-lg bg-black/50 backdrop-blur-md border border-white/10 text-text-secondary hover:text-white transition-all"
        >
          {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
        </button>
      </div>
      
      {/* Port Legend */}
      <div className="absolute bottom-4 left-4 bg-black/70 backdrop-blur-md rounded-xl p-3 border border-white/10">
        <div className="text-xs text-text-muted mb-2">Top Ports</div>
        <div className="grid grid-cols-4 gap-x-4 gap-y-1">
          {Object.entries(PORT_COLORS).slice(0, 8).map(([port, color]) => (
            <div key={port} className="flex items-center gap-1.5">
              <span 
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: color, boxShadow: `0 0 4px ${color}` }}
              />
              <span className="text-xs text-text-secondary">{port}</span>
            </div>
          ))}
        </div>
      </div>
      
      {/* Live Feed */}
      <div className="absolute bottom-4 right-4 bg-black/80 backdrop-blur-md rounded-xl border border-white/10 w-72 max-h-56 overflow-hidden">
        <div className="px-3 py-2 border-b border-white/10 flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${!isPaused ? 'bg-yellow-400 animate-ping' : 'bg-gray-500'}`}></span>
            <span className={`relative inline-flex rounded-full h-2 w-2 ${!isPaused ? 'bg-yellow-400' : 'bg-gray-500'}`}></span>
          </span>
          <span className="text-xs font-medium text-white">Blocked Traffic</span>
        </div>
        <div className="overflow-y-auto max-h-44">
          {recentList.map((attack, i) => (
            <div 
              key={attack.id}
              className="px-3 py-1.5 border-b border-white/5 hover:bg-white/5 transition-colors"
              style={{ opacity: 1 - i * 0.04 }}
            >
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <span 
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: getPortColor(attack.dst_port) }}
                  />
                  <span className="text-text-secondary">
                    {attack.src_country || 'Unknown'} → :{attack.dst_port}
                  </span>
                </div>
                <span className="text-text-muted">{formatTime(attack.timestamp)}</span>
              </div>
              <div className="text-xs font-mono mt-0.5 text-yellow-400/80">
                {attack.src_ip}
              </div>
            </div>
          ))}
          {recentList.length === 0 && (
            <div className="px-3 py-6 text-center text-text-muted text-xs">
              Waiting for blocked traffic...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

