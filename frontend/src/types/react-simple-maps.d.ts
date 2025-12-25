declare module 'react-simple-maps' {
  import { ComponentType, ReactNode } from 'react';

  export interface ProjectionConfig {
    scale?: number;
    center?: [number, number];
    rotate?: [number, number, number];
  }

  export interface ComposableMapProps {
    projection?: string;
    projectionConfig?: ProjectionConfig;
    width?: number;
    height?: number;
    style?: React.CSSProperties;
    children?: ReactNode;
  }

  export interface GeographiesChildProps {
    geographies: Geography[];
    outline: object;
    borders: object;
  }

  export interface Geography {
    rsmKey: string;
    type: string;
    properties: Record<string, unknown>;
    geometry: object;
  }

  export interface GeographiesProps {
    geography: string | object;
    children: (props: GeographiesChildProps) => ReactNode;
  }

  export interface GeographyStyleProps {
    default?: React.CSSProperties & { outline?: string };
    hover?: React.CSSProperties & { outline?: string };
    pressed?: React.CSSProperties & { outline?: string };
  }

  export interface GeographyProps {
    geography: Geography;
    fill?: string;
    stroke?: string;
    strokeWidth?: number;
    style?: GeographyStyleProps;
    onClick?: (event: React.MouseEvent) => void;
    onMouseEnter?: (event: React.MouseEvent) => void;
    onMouseLeave?: (event: React.MouseEvent) => void;
  }

  export interface MarkerProps {
    coordinates: [number, number];
    children?: ReactNode;
    onClick?: (event: React.MouseEvent) => void;
    onMouseEnter?: (event: React.MouseEvent) => void;
    onMouseLeave?: (event: React.MouseEvent) => void;
    style?: GeographyStyleProps;
  }

  export interface LineProps {
    from: [number, number];
    to: [number, number];
    stroke?: string;
    strokeWidth?: number;
    strokeLinecap?: 'butt' | 'round' | 'square';
    strokeDasharray?: string;
    fill?: string;
  }

  export const ComposableMap: ComponentType<ComposableMapProps>;
  export const Geographies: ComponentType<GeographiesProps>;
  export const Geography: ComponentType<GeographyProps>;
  export const Marker: ComponentType<MarkerProps>;
  export const Line: ComponentType<LineProps>;
  export const ZoomableGroup: ComponentType<{ center?: [number, number]; zoom?: number; children?: ReactNode }>;
}





