import { useState, useEffect, useRef, useCallback } from 'react';
import { Play, Pause, SkipForward, RotateCcw, Terminal } from 'lucide-react';

interface Command {
  timestamp: string;
  command: string;
  output?: string;
}

interface SessionReplayProps {
  commands: Command[];
  onComplete?: () => void;
  autoPlay?: boolean;
  speed?: number; // 1 = real time, 2 = 2x speed, etc.
}

export default function SessionReplay({
  commands,
  onComplete,
  autoPlay = false,
  speed = 2,
}: SessionReplayProps) {
  const [isPlaying, setIsPlaying] = useState(autoPlay);
  const [displayedCommands, setDisplayedCommands] = useState<Command[]>([]);
  const [currentTyping, setCurrentTyping] = useState('');
  const terminalRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>();
  const currentIndexRef = useRef(0);
  const isPlayingRef = useRef(isPlaying);

  // Keep refs in sync
  useEffect(() => {
    isPlayingRef.current = isPlaying;
  }, [isPlaying]);

  // Calculate delay between commands
  const getDelay = useCallback((cmd: Command, nextCmd?: Command) => {
    if (!nextCmd) return 1000;
    
    const current = new Date(cmd.timestamp).getTime();
    const next = new Date(nextCmd.timestamp).getTime();
    const realDelay = next - current;
    
    // Scale by speed, but cap at reasonable bounds
    return Math.min(Math.max(realDelay / speed, 200), 3000);
  }, [speed]);

  // Type out command character by character
  const typeCommand = useCallback((command: string, onDone: () => void) => {
    let charIndex = 0;
    const typingSpeed = 50 / speed; // ms per character
    
    const typeChar = () => {
      if (!isPlayingRef.current) return; // Stop if paused
      
      if (charIndex < command.length) {
        setCurrentTyping(command.slice(0, charIndex + 1));
        charIndex++;
        timeoutRef.current = setTimeout(typeChar, typingSpeed);
      } else {
        setCurrentTyping('');
        onDone();
      }
    };
    
    typeChar();
  }, [speed]);

  // Play next command using ref for current index
  const playNext = useCallback(() => {
    if (!isPlayingRef.current) return;
    
    const idx = currentIndexRef.current;
    if (idx >= commands.length) {
      setIsPlaying(false);
      onComplete?.();
      return;
    }

    const cmd = commands[idx];
    
    // Type out the command
    typeCommand(cmd.command, () => {
      if (!isPlayingRef.current) return;
      
      // Add to displayed commands
      setDisplayedCommands(prev => [...prev, cmd]);
      currentIndexRef.current = idx + 1;
      
      // Schedule next command
      const nextIdx = idx + 1;
      if (nextIdx < commands.length) {
        const delay = getDelay(cmd, commands[nextIdx]);
        timeoutRef.current = setTimeout(playNext, delay);
      } else {
        setIsPlaying(false);
        onComplete?.();
      }
    });
  }, [commands, typeCommand, getDelay, onComplete]);

  // Start/stop playback
  useEffect(() => {
    if (isPlaying) {
      // Clear any existing timeout
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      playNext();
    }
    
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [isPlaying, playNext]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [displayedCommands, currentTyping]);

  const handlePlay = () => {
    if (currentIndexRef.current >= commands.length) {
      // Reset and play
      currentIndexRef.current = 0;
      setDisplayedCommands([]);
    }
    setIsPlaying(true);
  };

  const handlePause = () => {
    setIsPlaying(false);
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
  };

  const handleReset = () => {
    setIsPlaying(false);
    currentIndexRef.current = 0;
    setDisplayedCommands([]);
    setCurrentTyping('');
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
  };

  const handleSkip = () => {
    // Show all commands at once
    setIsPlaying(false);
    setDisplayedCommands(commands);
    currentIndexRef.current = commands.length;
    setCurrentTyping('');
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
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

  const currentIndex = currentIndexRef.current;

  return (
    <div className="bg-bg-secondary rounded-xl border border-bg-hover overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-bg-hover bg-bg-card">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-neon-green" />
          <span className="text-sm font-medium text-white">Session Replay</span>
          <span className="text-xs text-text-muted">
            ({displayedCommands.length}/{commands.length} commands)
          </span>
        </div>
        
        {/* Controls */}
        <div className="flex items-center gap-1">
          <button
            onClick={handleReset}
            className="p-1.5 rounded hover:bg-bg-hover transition-colors text-text-muted hover:text-white"
            title="Reset"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          
          {isPlaying ? (
            <button
              onClick={handlePause}
              className="p-1.5 rounded bg-neon-orange/20 text-neon-orange hover:bg-neon-orange/30 transition-colors"
              title="Pause"
            >
              <Pause className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={handlePlay}
              className="p-1.5 rounded bg-neon-green/20 text-neon-green hover:bg-neon-green/30 transition-colors"
              title="Play"
            >
              <Play className="w-4 h-4" />
            </button>
          )}
          
          <button
            onClick={handleSkip}
            className="p-1.5 rounded hover:bg-bg-hover transition-colors text-text-muted hover:text-white"
            title="Skip to end"
          >
            <SkipForward className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal */}
      <div 
        ref={terminalRef}
        className="p-4 font-mono text-sm h-64 overflow-y-auto bg-[#0c0c0c]"
      >
        {displayedCommands.map((cmd, i) => (
          <div key={`${cmd.timestamp}-${i}`} className="mb-2">
            <div className="flex items-start gap-2">
              <span className="text-text-muted text-xs flex-shrink-0">{formatTime(cmd.timestamp)}</span>
              <span className="text-neon-green flex-shrink-0">$</span>
              <span className="text-white break-all">{cmd.command}</span>
            </div>
            {cmd.output && (
              <div className="ml-4 text-text-secondary whitespace-pre-wrap text-xs mt-1">
                {cmd.output}
              </div>
            )}
          </div>
        ))}
        
        {/* Currently typing */}
        {currentTyping && (
          <div className="flex items-start gap-2">
            <span className="text-neon-green flex-shrink-0">$</span>
            <span className="text-white break-all">{currentTyping}</span>
            <span className="w-2 h-4 bg-neon-green animate-pulse flex-shrink-0" />
          </div>
        )}
        
        {/* Empty prompt when idle */}
        {!isPlaying && !currentTyping && currentIndex >= commands.length && commands.length > 0 && (
          <div className="flex items-center gap-2 text-text-muted">
            <span>$</span>
            <span className="w-2 h-4 bg-text-muted/50 animate-pulse" />
          </div>
        )}
        
        {/* Empty state */}
        {commands.length === 0 && (
          <div className="text-text-muted text-center py-8">
            No commands to replay
          </div>
        )}
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-bg-hover">
        <div 
          className="h-full bg-neon-green transition-all duration-300"
          style={{ width: `${(displayedCommands.length / Math.max(commands.length, 1)) * 100}%` }}
        />
      </div>
    </div>
  );
}
