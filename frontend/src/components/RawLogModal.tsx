import { X, Copy, Download, Check } from 'lucide-react';
import { useState } from 'react';

interface RawLogModalProps {
  log: Record<string, unknown>;
  title?: string;
  onClose: () => void;
}

export default function RawLogModal({ log, title = 'Raw Log Entry', onClose }: RawLogModalProps) {
  const [copied, setCopied] = useState(false);

  const formattedLog = JSON.stringify(log, null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(formattedLog);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleDownload = () => {
    const blob = new Blob([formattedLog], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `log_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Syntax highlight JSON
  const highlightJSON = (json: string) => {
    return json
      .replace(/"([^"]+)":/g, '<span class="text-neon-blue">"$1"</span>:')
      .replace(/: "([^"]+)"/g, ': <span class="text-neon-orange">"$1"</span>')
      .replace(/: (\d+\.?\d*)/g, ': <span class="text-neon-green">$1</span>')
      .replace(/: (true|false)/g, ': <span class="text-neon-purple">$1</span>')
      .replace(/: (null)/g, ': <span class="text-text-secondary">$1</span>');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-bg-secondary rounded-xl border border-bg-hover shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-bg-hover bg-bg-card/50">
          <h2 className="text-lg font-display font-bold text-text-primary">
            {title}
          </h2>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopy}
              className="p-2 text-text-secondary hover:text-neon-green transition-colors flex items-center space-x-1"
              title="Copy to clipboard"
            >
              {copied ? (
                <Check className="w-5 h-5 text-neon-green" />
              ) : (
                <Copy className="w-5 h-5" />
              )}
            </button>
            <button
              onClick={handleDownload}
              className="p-2 text-text-secondary hover:text-neon-blue transition-colors"
              title="Download JSON"
            >
              <Download className="w-5 h-5" />
            </button>
            <button
              onClick={onClose}
              className="p-2 text-text-secondary hover:text-text-primary transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-auto" style={{ maxHeight: 'calc(90vh - 80px)' }}>
          <pre
            className="p-4 text-sm font-mono leading-relaxed text-text-primary overflow-x-auto"
            dangerouslySetInnerHTML={{ __html: highlightJSON(formattedLog) }}
          />
        </div>
      </div>
    </div>
  );
}


