import { ReactNode, CSSProperties } from 'react';

interface SkeletonProps {
  className?: string;
  children?: ReactNode;
  style?: CSSProperties;
}

// Base skeleton with shimmer animation
export function Skeleton({ className = '', style }: SkeletonProps) {
  return (
    <div 
      className={`animate-pulse bg-gradient-to-r from-bg-hover via-bg-card to-bg-hover bg-[length:200%_100%] rounded ${className}`}
      style={{ animation: 'shimmer 1.5s ease-in-out infinite', ...style }}
    />
  );
}

// Card skeleton
export function SkeletonCard({ className = '' }: SkeletonProps) {
  return (
    <div className={`bg-bg-card rounded-xl border border-bg-hover p-4 ${className}`}>
      <div className="flex items-center gap-3 mb-4">
        <Skeleton className="w-10 h-10 rounded-lg" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-3 w-16" />
        </div>
      </div>
      <Skeleton className="h-8 w-20" />
    </div>
  );
}

// Stats card skeleton
export function SkeletonStats({ className = '' }: SkeletonProps) {
  return (
    <div className={`bg-bg-card rounded-xl border border-bg-hover p-6 ${className}`}>
      <div className="flex items-center justify-between mb-4">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="w-8 h-8 rounded-lg" />
      </div>
      <Skeleton className="h-10 w-24 mb-2" />
      <Skeleton className="h-3 w-20" />
    </div>
  );
}

// Chart skeleton
export function SkeletonChart({ className = '', height = 'h-64' }: SkeletonProps & { height?: string }) {
  return (
    <div className={`bg-bg-card rounded-xl border border-bg-hover p-4 ${className}`}>
      <div className="flex items-center justify-between mb-4">
        <Skeleton className="h-5 w-40" />
        <Skeleton className="h-8 w-24 rounded-lg" />
      </div>
      <div className={`${height} relative`}>
        {/* Y-axis labels */}
        <div className="absolute left-0 top-0 bottom-8 w-8 flex flex-col justify-between">
          <Skeleton className="h-3 w-6" />
          <Skeleton className="h-3 w-8" />
          <Skeleton className="h-3 w-6" />
          <Skeleton className="h-3 w-8" />
        </div>
        {/* Chart area with bars */}
        <div className="ml-10 h-full flex items-end gap-2 pb-8">
          {[40, 65, 45, 80, 55, 70, 50, 75, 60, 85, 45, 70].map((h, i) => (
            <Skeleton 
              key={i} 
              className="flex-1 rounded-t" 
              style={{ height: `${h}%` }} 
            />
          ))}
        </div>
        {/* X-axis labels */}
        <div className="absolute left-10 right-0 bottom-0 flex justify-between">
          <Skeleton className="h-3 w-8" />
          <Skeleton className="h-3 w-8" />
          <Skeleton className="h-3 w-8" />
          <Skeleton className="h-3 w-8" />
        </div>
      </div>
    </div>
  );
}

// Table skeleton
export function SkeletonTable({ rows = 5, columns = 4, className = '' }: SkeletonProps & { rows?: number; columns?: number }) {
  return (
    <div className={`bg-bg-card rounded-xl border border-bg-hover overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex gap-4 p-4 border-b border-bg-hover bg-bg-secondary">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-4 flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIdx) => (
        <div key={rowIdx} className="flex gap-4 p-4 border-b border-bg-hover/50 last:border-0">
          {Array.from({ length: columns }).map((_, colIdx) => (
            <Skeleton 
              key={colIdx} 
              className={`h-4 flex-1 ${colIdx === 0 ? 'w-1/4' : ''}`} 
            />
          ))}
        </div>
      ))}
    </div>
  );
}

// Text line skeleton
export function SkeletonText({ lines = 3, className = '' }: SkeletonProps & { lines?: number }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton 
          key={i} 
          className={`h-4 ${i === lines - 1 ? 'w-3/4' : 'w-full'}`} 
        />
      ))}
    </div>
  );
}

// KPI Grid skeleton
export function SkeletonKPIGrid({ count = 4, className = '' }: SkeletonProps & { count?: number }) {
  return (
    <div className={`grid grid-cols-2 md:grid-cols-4 gap-4 ${className}`}>
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonStats key={i} />
      ))}
    </div>
  );
}

// Dashboard skeleton
export function SkeletonDashboard() {
  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* KPIs */}
      <SkeletonKPIGrid count={4} />
      
      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonChart />
        <SkeletonChart />
      </div>
      
      {/* Table */}
      <SkeletonTable rows={5} columns={5} />
    </div>
  );
}

// Add CSS for shimmer animation to your global styles
// @keyframes shimmer {
//   0% { background-position: 200% 0; }
//   100% { background-position: -200% 0; }
// }

export default Skeleton;

