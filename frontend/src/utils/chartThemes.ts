// Chart color themes per honeypot type
export const CHART_THEMES = {
  cowrie: {
    primary: '#39ff14',
    secondary: '#2ed10d',
    gradient: {
      start: '#39ff14',
      startOpacity: 0.4,
      end: '#39ff14',
      endOpacity: 0,
    },
    accent: '#00ff88',
    background: 'rgba(57, 255, 20, 0.1)',
  },
  dionaea: {
    primary: '#00d4ff',
    secondary: '#00a8cc',
    gradient: {
      start: '#00d4ff',
      startOpacity: 0.4,
      end: '#00d4ff',
      endOpacity: 0,
    },
    accent: '#00ffff',
    background: 'rgba(0, 212, 255, 0.1)',
  },
  galah: {
    primary: '#ff6600',
    secondary: '#cc5200',
    gradient: {
      start: '#ff6600',
      startOpacity: 0.4,
      end: '#ff6600',
      endOpacity: 0,
    },
    accent: '#ff9933',
    background: 'rgba(255, 102, 0, 0.1)',
  },
  rdpy: {
    primary: '#bf00ff',
    secondary: '#9900cc',
    gradient: {
      start: '#bf00ff',
      startOpacity: 0.4,
      end: '#bf00ff',
      endOpacity: 0,
    },
    accent: '#cc66ff',
    background: 'rgba(191, 0, 255, 0.1)',
  },
  heralding: {
    primary: '#ff3366',
    secondary: '#cc2952',
    gradient: {
      start: '#ff3366',
      startOpacity: 0.4,
      end: '#ff3366',
      endOpacity: 0,
    },
    accent: '#ff6699',
    background: 'rgba(255, 51, 102, 0.1)',
  },
  firewall: {
    primary: '#ffcc00',
    secondary: '#cc9900',
    gradient: {
      start: '#ffcc00',
      startOpacity: 0.4,
      end: '#ffcc00',
      endOpacity: 0,
    },
    accent: '#ffe066',
    background: 'rgba(255, 204, 0, 0.1)',
  },
  default: {
    primary: '#888888',
    secondary: '#666666',
    gradient: {
      start: '#888888',
      startOpacity: 0.4,
      end: '#888888',
      endOpacity: 0,
    },
    accent: '#aaaaaa',
    background: 'rgba(136, 136, 136, 0.1)',
  },
};

export type HoneypotType = keyof typeof CHART_THEMES;

export function getChartTheme(honeypot: string) {
  return CHART_THEMES[honeypot as HoneypotType] || CHART_THEMES.default;
}

// Multi-series colors for combined charts
export const MULTI_SERIES_COLORS = [
  '#39ff14', // green
  '#00d4ff', // blue
  '#ff6600', // orange
  '#bf00ff', // purple
  '#ff3366', // red
  '#ffcc00', // yellow
  '#00ffcc', // cyan
  '#ff00ff', // magenta
];

// Common chart styling
export const CHART_STYLES = {
  tooltip: {
    contentStyle: {
      backgroundColor: 'rgba(26, 26, 37, 0.95)',
      border: '1px solid rgba(255,255,255,0.1)',
      borderRadius: '8px',
      boxShadow: '0 4px 20px rgba(0,0,0,0.5)',
    },
    labelStyle: {
      color: '#e0e0e0',
    },
  },
  axis: {
    stroke: '#555',
    tick: { fill: '#888', fontSize: 11 },
    axisLine: false,
  },
  grid: {
    stroke: 'rgba(255,255,255,0.05)',
    strokeDasharray: '3 3',
  },
};

// Generate gradient ID for SVG
export function getGradientId(honeypot: string) {
  return `gradient-${honeypot}`;
}

// Generate gradient definition for Recharts
export function generateGradientDef(honeypot: string, id?: string) {
  const theme = getChartTheme(honeypot);
  const gradientId = id || getGradientId(honeypot);
  
  return {
    id: gradientId,
    x1: '0',
    y1: '0',
    x2: '0',
    y2: '1',
    stops: [
      { offset: '0%', stopColor: theme.gradient.start, stopOpacity: theme.gradient.startOpacity },
      { offset: '100%', stopColor: theme.gradient.end, stopOpacity: theme.gradient.endOpacity },
    ],
  };
}




