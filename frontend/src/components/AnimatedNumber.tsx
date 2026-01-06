import { useEffect, useState, useRef } from 'react';

interface AnimatedNumberProps {
  value: number;
  duration?: number; // Animation duration in ms
  formatFn?: (n: number) => string;
  className?: string;
  prefix?: string;
  suffix?: string;
}

export default function AnimatedNumber({
  value,
  duration = 500,
  formatFn = (n) => n.toLocaleString(),
  className = '',
  prefix = '',
  suffix = '',
}: AnimatedNumberProps) {
  const [displayValue, setDisplayValue] = useState(value);
  const previousValue = useRef(value);
  const animationRef = useRef<number>();

  useEffect(() => {
    const startValue = previousValue.current;
    const endValue = value;
    const startTime = performance.now();

    // Easing function (ease-out cubic)
    const easeOutCubic = (t: number) => 1 - Math.pow(1 - t, 3);

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easedProgress = easeOutCubic(progress);

      const currentValue = startValue + (endValue - startValue) * easedProgress;
      setDisplayValue(Math.round(currentValue));

      if (progress < 1) {
        animationRef.current = requestAnimationFrame(animate);
      } else {
        setDisplayValue(endValue);
        previousValue.current = endValue;
      }
    };

    // Only animate if the change is significant
    if (Math.abs(endValue - startValue) > 0) {
      animationRef.current = requestAnimationFrame(animate);
    } else {
      setDisplayValue(value);
    }

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [value, duration]);

  return (
    <span className={className}>
      {prefix}
      {formatFn(displayValue)}
      {suffix}
    </span>
  );
}

// Specialized counter with color flash on increase
export function FlashingCounter({
  value,
  className = '',
  highlightColor = '#39ff14',
}: {
  value: number;
  className?: string;
  highlightColor?: string;
}) {
  const [flash, setFlash] = useState(false);
  const previousValue = useRef(value);

  useEffect(() => {
    if (value > previousValue.current) {
      setFlash(true);
      const timer = setTimeout(() => setFlash(false), 300);
      previousValue.current = value;
      return () => clearTimeout(timer);
    }
    previousValue.current = value;
  }, [value]);

  return (
    <span
      className={`transition-all duration-300 ${className}`}
      style={{
        textShadow: flash ? `0 0 20px ${highlightColor}` : 'none',
        color: flash ? highlightColor : undefined,
      }}
    >
      <AnimatedNumber value={value} />
    </span>
  );
}

// Percentage with animated bar
export function AnimatedPercentage({
  value,
  max = 100,
  label,
  color = '#39ff14',
  className = '',
}: {
  value: number;
  max?: number;
  label?: string;
  color?: string;
  className?: string;
}) {
  const percentage = Math.min((value / max) * 100, 100);

  return (
    <div className={className}>
      {label && (
        <div className="flex items-center justify-between text-sm mb-1">
          <span className="text-text-secondary">{label}</span>
          <AnimatedNumber 
            value={percentage} 
            suffix="%" 
            className="font-mono text-white"
            formatFn={(n) => n.toFixed(1)}
          />
        </div>
      )}
      <div className="h-2 bg-bg-hover rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500 ease-out"
          style={{
            width: `${percentage}%`,
            backgroundColor: color,
            boxShadow: `0 0 10px ${color}50`,
          }}
        />
      </div>
    </div>
  );
}




