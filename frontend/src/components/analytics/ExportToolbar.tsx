import { useState } from 'react';
import { Download, FileText, Image, Loader2 } from 'lucide-react';

interface ExportToolbarProps {
  onExportCSV?: () => void;
  onExportPNG?: () => void;
  onExportPDF?: () => void;
  csvDisabled?: boolean;
  pngDisabled?: boolean;
  pdfDisabled?: boolean;
  loading?: boolean;
}

export default function ExportToolbar({
  onExportCSV,
  onExportPNG,
  onExportPDF,
  csvDisabled = false,
  pngDisabled = false,
  pdfDisabled = false,
  loading = false,
}: ExportToolbarProps) {
  const [exporting, setExporting] = useState<'csv' | 'png' | 'pdf' | null>(null);

  const handleExport = async (type: 'csv' | 'png' | 'pdf', handler?: () => void | Promise<void>) => {
    if (!handler) return;
    
    setExporting(type);
    try {
      await handler();
    } finally {
      setExporting(null);
    }
  };

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-text-muted mr-1">Export:</span>
      
      {/* CSV Export */}
      {onExportCSV && (
        <button
          onClick={() => handleExport('csv', onExportCSV)}
          disabled={csvDisabled || loading || exporting !== null}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary hover:border-neon-green/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {exporting === 'csv' ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <FileText className="w-4 h-4" />
          )}
          <span>CSV</span>
        </button>
      )}

      {/* PNG Export */}
      {onExportPNG && (
        <button
          onClick={() => handleExport('png', onExportPNG)}
          disabled={pngDisabled || loading || exporting !== null}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary hover:border-neon-green/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {exporting === 'png' ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Image className="w-4 h-4" />
          )}
          <span>PNG</span>
        </button>
      )}

      {/* PDF Export */}
      {onExportPDF && (
        <button
          onClick={() => handleExport('pdf', onExportPDF)}
          disabled={pdfDisabled || loading || exporting !== null}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-bg-secondary border border-bg-hover rounded-md text-sm text-text-primary hover:border-neon-green/50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {exporting === 'pdf' ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Download className="w-4 h-4" />
          )}
          <span>PDF</span>
        </button>
      )}
    </div>
  );
}

// Utility functions for exports

export function exportToCSV(data: Record<string, unknown>[], filename: string) {
  if (!data.length) return;

  const headers = Object.keys(data[0]);
  const csvContent = [
    headers.join(','),
    ...data.map(row => 
      headers.map(header => {
        const value = row[header];
        const strValue = typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
        // Escape quotes and wrap in quotes if contains comma
        if (strValue.includes(',') || strValue.includes('"') || strValue.includes('\n')) {
          return `"${strValue.replace(/"/g, '""')}"`;
        }
        return strValue;
      }).join(',')
    )
  ].join('\n');

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${filename}_${new Date().toISOString().split('T')[0]}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

export async function exportToPNG(elementId: string, filename: string) {
  const element = document.getElementById(elementId);
  if (!element) return;

  const html2canvas = (await import('html2canvas')).default;
  const canvas = await html2canvas(element, {
    backgroundColor: '#0d0d14',
    scale: 2,
  });

  const link = document.createElement('a');
  link.download = `${filename}_${new Date().toISOString().split('T')[0]}.png`;
  link.href = canvas.toDataURL('image/png');
  link.click();
}

