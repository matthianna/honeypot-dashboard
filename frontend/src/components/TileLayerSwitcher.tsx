import { Map, Layers, Satellite, Mountain } from 'lucide-react';

export type TileLayerType = 'dark' | 'street' | 'satellite' | 'terrain';

export const TILE_LAYERS: Record<TileLayerType, { url: string; attribution: string; name: string }> = {
  dark: {
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
    name: 'Dark',
  },
  street: {
    url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    name: 'Street',
  },
  satellite: {
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community',
    name: 'Satellite',
  },
  terrain: {
    url: 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
    attribution: 'Map data: &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors, SRTM | Map style: &copy; <a href="https://opentopomap.org">OpenTopoMap</a>',
    name: 'Terrain',
  },
};

interface TileLayerSwitcherProps {
  currentLayer: TileLayerType;
  onChange: (layer: TileLayerType) => void;
  isOpen: boolean;
  onToggle: () => void;
}

const LAYER_ICONS: Record<TileLayerType, React.ReactNode> = {
  dark: <Map className="w-4 h-4" />,
  street: <Layers className="w-4 h-4" />,
  satellite: <Satellite className="w-4 h-4" />,
  terrain: <Mountain className="w-4 h-4" />,
};

export default function TileLayerSwitcher({ 
  currentLayer, 
  onChange, 
  isOpen, 
  onToggle 
}: TileLayerSwitcherProps) {
  return (
    <div className="relative">
      {/* Toggle button */}
      <button
        onClick={onToggle}
        className={`p-3 rounded-lg backdrop-blur-md border transition-all ${
          isOpen
            ? 'bg-neon-blue/20 border-neon-blue text-neon-blue'
            : 'bg-black/50 border-white/10 text-text-secondary hover:text-white'
        }`}
        title="Change Map Style"
      >
        <Layers className="w-5 h-5" />
      </button>
      
      {/* Dropdown panel */}
      {isOpen && (
        <div className="absolute top-full right-0 mt-2 bg-black/90 backdrop-blur-md rounded-xl border border-white/10 overflow-hidden min-w-[160px] z-[1000]">
          <div className="px-3 py-2 border-b border-white/10">
            <span className="text-xs uppercase tracking-wider text-text-muted">Map Style</span>
          </div>
          {(Object.keys(TILE_LAYERS) as TileLayerType[]).map((layer) => (
            <button
              key={layer}
              onClick={() => {
                onChange(layer);
                onToggle();
              }}
              className={`w-full flex items-center gap-3 px-4 py-3 transition-colors ${
                currentLayer === layer
                  ? 'bg-neon-blue/20 text-neon-blue'
                  : 'text-text-secondary hover:bg-white/5 hover:text-white'
              }`}
            >
              {LAYER_ICONS[layer]}
              <span className="text-sm">{TILE_LAYERS[layer].name}</span>
              {currentLayer === layer && (
                <span className="ml-auto w-2 h-2 rounded-full bg-neon-blue" />
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}









