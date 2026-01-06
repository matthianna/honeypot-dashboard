/**
 * Accessibility utilities for ARIA labels and keyboard navigation
 */

// Screen reader only class (visually hidden but accessible)
export const srOnly = 'absolute w-px h-px p-0 -m-px overflow-hidden whitespace-nowrap border-0';

// Announce message to screen readers
export function announceToScreenReader(message: string, priority: 'polite' | 'assertive' = 'polite') {
  const announcement = document.createElement('div');
  announcement.setAttribute('role', 'status');
  announcement.setAttribute('aria-live', priority);
  announcement.setAttribute('aria-atomic', 'true');
  announcement.className = srOnly;
  announcement.textContent = message;
  
  document.body.appendChild(announcement);
  
  // Remove after announcement
  setTimeout(() => {
    document.body.removeChild(announcement);
  }, 1000);
}

// Common ARIA label helpers
export const ariaLabels = {
  // Navigation
  sidebar: 'Main navigation sidebar',
  mainContent: 'Main content area',
  breadcrumb: 'Breadcrumb navigation',
  
  // Tables
  sortAscending: (column: string) => `Sort by ${column} ascending`,
  sortDescending: (column: string) => `Sort by ${column} descending`,
  
  // Charts
  chartDescription: (type: string, title: string) => `${type} chart showing ${title}`,
  
  // Buttons
  close: 'Close',
  expand: 'Expand',
  collapse: 'Collapse',
  search: 'Search',
  filter: 'Filter',
  refresh: 'Refresh data',
  export: 'Export data',
  
  // Status
  loading: 'Loading...',
  noData: 'No data available',
  error: 'An error occurred',
  
  // Map
  attackMarker: (ip: string, country: string) => `Attack from ${ip}, ${country}`,
  targetMarker: 'Target location: Zurich, Switzerland',
};

// Keyboard navigation helpers
export const keyboardHandlers = {
  // Handle Enter/Space as click
  onActivate: (callback: () => void) => (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      callback();
    }
  },
  
  // Handle Escape
  onEscape: (callback: () => void) => (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      callback();
    }
  },
  
  // Arrow key navigation
  onArrowKeys: (handlers: {
    up?: () => void;
    down?: () => void;
    left?: () => void;
    right?: () => void;
  }) => (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowUp':
        if (handlers.up) {
          e.preventDefault();
          handlers.up();
        }
        break;
      case 'ArrowDown':
        if (handlers.down) {
          e.preventDefault();
          handlers.down();
        }
        break;
      case 'ArrowLeft':
        if (handlers.left) {
          e.preventDefault();
          handlers.left();
        }
        break;
      case 'ArrowRight':
        if (handlers.right) {
          e.preventDefault();
          handlers.right();
        }
        break;
    }
  },
};

// Focus trap for modals
export function createFocusTrap(container: HTMLElement) {
  const focusableElements = container.querySelectorAll<HTMLElement>(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
  );
  
  const firstElement = focusableElements[0];
  const lastElement = focusableElements[focusableElements.length - 1];
  
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key !== 'Tab') return;
    
    if (e.shiftKey) {
      if (document.activeElement === firstElement) {
        e.preventDefault();
        lastElement?.focus();
      }
    } else {
      if (document.activeElement === lastElement) {
        e.preventDefault();
        firstElement?.focus();
      }
    }
  };
  
  container.addEventListener('keydown', handleKeyDown);
  firstElement?.focus();
  
  return () => {
    container.removeEventListener('keydown', handleKeyDown);
  };
}

// Classes for skip to main content link
export const skipToMainClasses = 'sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-[9999] focus:px-4 focus:py-2 focus:bg-neon-green focus:text-bg-primary focus:rounded-lg focus:font-medium';

// Classes for visually hidden but accessible text
export const visuallyHiddenClasses = srOnly;

