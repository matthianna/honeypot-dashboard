import { useMemo } from 'react';
import { Clock, Terminal, User } from 'lucide-react';

interface Session {
  id: string;
  start: string;
  end?: string;
  duration?: number; // seconds
  src_ip: string;
  commands?: number;
  variant?: string;
}

interface SessionTimelineProps {
  sessions: Session[];
  timeRange: { start: Date; end: Date };
  onSessionClick?: (session: Session) => void;
  className?: string;
}

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
  default: '#888888',
};

export default function SessionTimeline({
  sessions,
  timeRange,
  onSessionClick,
  className = '',
}: SessionTimelineProps) {
  const totalDuration = timeRange.end.getTime() - timeRange.start.getTime();

  // Sort sessions by start time
  const sortedSessions = useMemo(() => {
    return [...sessions].sort((a, b) => 
      new Date(a.start).getTime() - new Date(b.start).getTime()
    );
  }, [sessions]);

  // Group overlapping sessions into rows
  const rows = useMemo(() => {
    const result: Session[][] = [];
    
    sortedSessions.forEach(session => {
      const sessionStart = new Date(session.start).getTime();
      
      // Find a row where this session fits (no overlap)
      let placed = false;
      for (const row of result) {
        const lastInRow = row[row.length - 1];
        const lastEnd = lastInRow.end 
          ? new Date(lastInRow.end).getTime() 
          : new Date(lastInRow.start).getTime() + (lastInRow.duration || 60) * 1000;
        
        if (sessionStart >= lastEnd) {
          row.push(session);
          placed = true;
          break;
        }
      }
      
      if (!placed) {
        result.push([session]);
      }
    });
    
    return result;
  }, [sortedSessions]);

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  const getPosition = (session: Session) => {
    const sessionStart = new Date(session.start).getTime();
    const sessionEnd = session.end 
      ? new Date(session.end).getTime() 
      : sessionStart + (session.duration || 60) * 1000;
    
    const left = ((sessionStart - timeRange.start.getTime()) / totalDuration) * 100;
    const width = ((sessionEnd - sessionStart) / totalDuration) * 100;
    
    return {
      left: `${Math.max(0, Math.min(left, 100))}%`,
      width: `${Math.max(0.5, Math.min(width, 100 - left))}%`,
    };
  };

  const hourMarkers = useMemo(() => {
    const markers = [];
    const start = new Date(timeRange.start);
    start.setMinutes(0, 0, 0);
    
    while (start <= timeRange.end) {
      const position = ((start.getTime() - timeRange.start.getTime()) / totalDuration) * 100;
      if (position >= 0 && position <= 100) {
        markers.push({
          time: new Date(start),
          position,
        });
      }
      start.setHours(start.getHours() + 1);
    }
    
    return markers;
  }, [timeRange, totalDuration]);

  return (
    <div className={`bg-bg-card rounded-xl border border-bg-hover overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-bg-hover">
        <div className="flex items-center gap-2">
          <Clock className="w-5 h-5 text-neon-green" />
          <span className="font-display font-bold text-white">Session Timeline</span>
          <span className="text-xs text-text-muted">({sessions.length} sessions)</span>
        </div>
        <div className="text-xs text-text-muted">
          {formatTime(timeRange.start)} - {formatTime(timeRange.end)}
        </div>
      </div>

      {/* Timeline */}
      <div className="p-4">
        {/* Time axis */}
        <div className="relative h-6 mb-2">
          {hourMarkers.map((marker, i) => (
            <div
              key={i}
              className="absolute flex flex-col items-center"
              style={{ left: `${marker.position}%` }}
            >
              <div className="text-xs text-text-muted">
                {formatTime(marker.time)}
              </div>
            </div>
          ))}
        </div>

        {/* Sessions grid */}
        <div className="relative min-h-[200px] border-l border-r border-bg-hover">
          {/* Vertical grid lines */}
          {hourMarkers.map((marker, i) => (
            <div
              key={i}
              className="absolute top-0 bottom-0 border-l border-bg-hover/50"
              style={{ left: `${marker.position}%` }}
            />
          ))}

          {/* Session rows */}
          {rows.map((row, rowIndex) => (
            <div
              key={rowIndex}
              className="relative h-10 mb-1"
            >
              {row.map((session) => {
                const pos = getPosition(session);
                const color = VARIANT_COLORS[session.variant || 'default'] || VARIANT_COLORS.default;
                
                return (
                  <button
                    key={session.id}
                    onClick={() => onSessionClick?.(session)}
                    className="absolute h-8 top-1 rounded-md transition-all hover:scale-105 hover:z-10 group"
                    style={{
                      left: pos.left,
                      width: pos.width,
                      minWidth: '8px',
                      backgroundColor: `${color}20`,
                      borderLeft: `3px solid ${color}`,
                    }}
                    title={`${session.src_ip} - ${session.commands || 0} commands`}
                  >
                    <div className="h-full flex items-center px-2 overflow-hidden">
                      <span className="text-xs truncate" style={{ color }}>
                        {session.src_ip.split('.').slice(-1)[0]}
                      </span>
                      {session.commands && session.commands > 0 && (
                        <span className="ml-1 flex items-center gap-0.5 text-xs text-text-muted">
                          <Terminal className="w-3 h-3" />
                          {session.commands}
                        </span>
                      )}
                    </div>
                    
                    {/* Hover tooltip */}
                    <div className="absolute left-0 bottom-full mb-1 bg-bg-card border border-bg-hover rounded-lg p-2 shadow-xl opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-20 whitespace-nowrap text-xs">
                      <div className="flex items-center gap-2 text-white font-medium">
                        <User className="w-3 h-3" />
                        {session.src_ip}
                      </div>
                      <div className="flex items-center gap-2 text-text-muted mt-1">
                        <Clock className="w-3 h-3" />
                        {session.duration ? `${session.duration.toFixed(1)}s` : 'N/A'}
                      </div>
                      {session.commands !== undefined && (
                        <div className="flex items-center gap-2 text-text-muted mt-1">
                          <Terminal className="w-3 h-3" />
                          {session.commands} commands
                        </div>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          ))}

          {/* Empty state */}
          {sessions.length === 0 && (
            <div className="absolute inset-0 flex items-center justify-center text-text-muted">
              No sessions in this time range
            </div>
          )}
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 mt-4 pt-4 border-t border-bg-hover">
          {Object.entries(VARIANT_COLORS).filter(([k]) => k !== 'default').map(([variant, color]) => (
            <div key={variant} className="flex items-center gap-2 text-xs">
              <div className="w-3 h-3 rounded" style={{ backgroundColor: color }} />
              <span className="text-text-muted capitalize">{variant}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

