import { useEffect, useState } from 'react';
import { CircleMarker, Popup, useMap } from 'react-leaflet';
import type { LatLngExpression } from 'leaflet';

// Honeypot colors
const HONEYPOT_COLORS: Record<string, string> = {
  cowrie: '#39ff14',
  dionaea: '#00d4ff',
  galah: '#ff6600',
  rdpy: '#bf00ff',
  heralding: '#ff3366',
  firewall: '#ffcc00',
};

// How long before removal to start fading (seconds)
const FADE_START = 100; // Start fading at 100 seconds (20 sec fade)
const FADE_DURATION = 20; // Fade over 20 seconds

export interface AttackData {
  id: string;
  timestamp: string;
  honeypot: string;
  src_ip: string;
  src_lat: number;
  src_lon: number;
  src_country: string | null;
  port: number | null;
}

interface AttackMarkerProps {
  attack: AttackData;
  age: number; // Age in seconds
}

export default function AttackMarker({ attack, age }: AttackMarkerProps) {
  const [pulsePhase, setPulsePhase] = useState(0);
  const map = useMap();
  
  const color = HONEYPOT_COLORS[attack.honeypot] || '#ffffff';
  const position: LatLngExpression = [attack.src_lat, attack.src_lon];
  
  // Calculate opacity - stay full until FADE_START, then fade over FADE_DURATION
  const opacity = age < FADE_START ? 1 : Math.max(0, 1 - (age - FADE_START) / FADE_DURATION);
  
  // Initial burst effect (first 0.5 seconds)
  const isBurst = age < 0.5;
  const burstScale = isBurst ? 1 + (0.5 - age) * 4 : 1;
  
  // Pulse animation
  useEffect(() => {
    const interval = setInterval(() => {
      setPulsePhase(prev => (prev + 1) % 100);
    }, 30);
    
    return () => clearInterval(interval);
  }, []);
  
  if (opacity <= 0) return null;
  
  const zoom = map.getZoom();
  const baseRadius = Math.max(5, 14 - zoom / 2);
  const pulseRadius = baseRadius + Math.sin(pulsePhase * 0.15) * 6;
  
  return (
    <>
      {/* Outer expanding ring (burst effect) */}
      {isBurst && (
        <CircleMarker
          center={position}
          radius={baseRadius * burstScale * 2}
          pathOptions={{
            color: color,
            fillColor: 'transparent',
            fillOpacity: 0,
            weight: 2,
            opacity: opacity * 0.5,
          }}
        />
      )}
      
      {/* Pulsing ring */}
      <CircleMarker
        center={position}
        radius={pulseRadius}
        pathOptions={{
          color: color,
          fillColor: 'transparent',
          fillOpacity: 0,
          weight: 1,
          opacity: opacity * 0.4,
        }}
      />
      
      {/* Glow effect */}
      <CircleMarker
        center={position}
        radius={baseRadius + 3}
        pathOptions={{
          color: 'transparent',
          fillColor: color,
          fillOpacity: opacity * 0.25,
          weight: 0,
        }}
      />
      
      {/* Core marker */}
      <CircleMarker
        center={position}
        radius={baseRadius * (isBurst ? burstScale : 1)}
        pathOptions={{
          color: color,
          fillColor: color,
          fillOpacity: opacity * 0.9,
          weight: 2,
          opacity: opacity,
        }}
      >
        <Popup>
          <div className="text-sm min-w-[160px]">
            <div className="font-bold text-base mb-2" style={{ color }}>
              {attack.honeypot.toUpperCase()}
            </div>
            <div className="space-y-1">
              <div className="flex justify-between">
                <span className="text-gray-500">IP:</span>
                <span className="font-mono">{attack.src_ip}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Country:</span>
                <span>{attack.src_country || 'Unknown'}</span>
              </div>
              {attack.port && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Port:</span>
                  <span className="font-mono">{attack.port}</span>
                </div>
              )}
            </div>
            <div className="text-xs text-gray-400 mt-2 pt-2 border-t border-gray-200">
              {new Date(attack.timestamp).toLocaleString()}
            </div>
          </div>
        </Popup>
      </CircleMarker>
    </>
  );
}

// Target marker - defaults to Zurich, can be customized
export function TargetMarker({ 
  position: customPosition,
  label = 'Zurich, Switzerland'
}: { 
  position?: [number, number];
  label?: string;
} = {}) {
  const position: LatLngExpression = customPosition || [47.3769, 8.5417];
  const [pulseSize, setPulseSize] = useState(0);
  
  useEffect(() => {
    const interval = setInterval(() => {
      setPulseSize(prev => (prev + 0.3) % 15);
    }, 50);
    return () => clearInterval(interval);
  }, []);
  
  return (
    <>
      {/* Outer pulse */}
      <CircleMarker
        center={position}
        radius={15 + pulseSize}
        pathOptions={{
          color: '#ffffff',
          fillColor: 'transparent',
          fillOpacity: 0,
          weight: 2,
          opacity: 0.5 - pulseSize / 30,
        }}
      />
      
      {/* Inner glow */}
      <CircleMarker
        center={position}
        radius={10}
        pathOptions={{
          color: '#ffffff',
          fillColor: '#ffffff',
          fillOpacity: 0.3,
          weight: 2,
          opacity: 0.8,
        }}
      />
      
      {/* Core */}
      <CircleMarker
        center={position}
        radius={5}
        pathOptions={{
          color: '#ffffff',
          fillColor: '#ffffff',
          fillOpacity: 1,
          weight: 2,
          opacity: 1,
        }}
      >
        <Popup>
          <div className="text-sm font-bold">
            🎯 Target: {label}
          </div>
        </Popup>
      </CircleMarker>
    </>
  );
}







