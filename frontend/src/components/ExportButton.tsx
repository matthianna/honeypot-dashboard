import { useState } from 'react';
import { Download, FileJson, FileSpreadsheet, ChevronDown } from 'lucide-react';
import { exportToJSON, exportToCSV, getExportFilename } from '../utils/export';

// Use a more flexible type that accepts any serializable data
type ExportData = unknown[] | Record<string, unknown> | (() => Promise<unknown[] | Record<string, unknown>>);

interface ExportButtonProps {
  data: ExportData;
  filename: string;
  timeRange?: string;
  disabled?: boolean;
  className?: string;
}

export default function ExportButton({ 
  data, 
  filename, 
  timeRange, 
  disabled = false,
  className = ''
}: ExportButtonProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async (format: 'json' | 'csv') => {
    setIsExporting(true);
    try {
      // Resolve data if it's a function
      const resolvedData = typeof data === 'function' ? await data() : data;
      const exportFilename = getExportFilename(filename, timeRange);

      if (format === 'json') {
        exportToJSON({ filename: exportFilename, data: resolvedData as Record<string, unknown> | Record<string, unknown>[] });
      } else {
        exportToCSV({ filename: exportFilename, data: resolvedData as Record<string, unknown> | Record<string, unknown>[] });
      }
    } catch (error) {
      console.error('Export failed:', error);
    } finally {
      setIsExporting(false);
      setIsOpen(false);
    }
  };

  return (
    <div className={`relative ${className}`}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        disabled={disabled || isExporting}
        className={`flex items-center gap-2 px-3 py-2 text-sm rounded-lg border transition-all ${
          disabled || isExporting
            ? 'bg-bg-hover border-bg-hover text-text-muted cursor-not-allowed'
            : 'bg-bg-secondary border-bg-hover text-text-secondary hover:text-text-primary hover:border-neon-green/50'
        }`}
      >
        <Download className={`w-4 h-4 ${isExporting ? 'animate-pulse' : ''}`} />
        <span>{isExporting ? 'Exporting...' : 'Export'}</span>
        <ChevronDown className={`w-3 h-3 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && !disabled && (
        <>
          {/* Backdrop */}
          <div 
            className="fixed inset-0 z-40" 
            onClick={() => setIsOpen(false)} 
          />
          
          {/* Dropdown */}
          <div className="absolute top-full right-0 mt-1 bg-bg-secondary border border-bg-hover rounded-lg shadow-xl overflow-hidden z-50 min-w-[140px]">
            <button
              onClick={() => handleExport('json')}
              className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-text-secondary hover:text-neon-blue hover:bg-bg-hover transition-colors"
            >
              <FileJson className="w-4 h-4" />
              <span>Export JSON</span>
            </button>
            <button
              onClick={() => handleExport('csv')}
              className="w-full flex items-center gap-2 px-4 py-2.5 text-sm text-text-secondary hover:text-neon-green hover:bg-bg-hover transition-colors"
            >
              <FileSpreadsheet className="w-4 h-4" />
              <span>Export CSV</span>
            </button>
          </div>
        </>
      )}
    </div>
  );
}

