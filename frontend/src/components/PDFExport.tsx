import { useState } from 'react';
import { Download, FileText, Loader2 } from 'lucide-react';

interface PDFExportProps {
  targetId: string;
  filename?: string;
  title?: string;
  className?: string;
}

export default function PDFExport({ 
  targetId, 
  filename = 'report', 
  title = 'Export PDF',
  className = '' 
}: PDFExportProps) {
  const [exporting, setExporting] = useState(false);

  const handleExport = async () => {
    setExporting(true);
    try {
      // Dynamic import for PDF libraries to reduce bundle size
      const html2canvas = (await import('html2canvas')).default;
      const { jsPDF } = await import('jspdf');
      
      const element = document.getElementById(targetId);
      if (!element) {
        console.error(`Element with id "${targetId}" not found`);
        return;
      }

      // Create canvas from HTML element
      const canvas = await html2canvas(element, {
        scale: 2,
        useCORS: true,
        logging: false,
        backgroundColor: '#0a0a0f',
        windowWidth: element.scrollWidth,
        windowHeight: element.scrollHeight,
      });

      // Calculate PDF dimensions
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      });

      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const imgWidth = canvas.width;
      const imgHeight = canvas.height;
      
      // Calculate scaling to fit width while maintaining aspect ratio
      const ratio = pdfWidth / imgWidth;
      const scaledHeight = imgHeight * ratio;
      
      // Add pages as needed
      let heightLeft = scaledHeight;
      let position = 0;
      let page = 0;

      while (heightLeft > 0) {
        if (page > 0) {
          pdf.addPage();
        }
        
        pdf.addImage(
          imgData,
          'PNG',
          0,
          position,
          pdfWidth,
          scaledHeight
        );
        
        heightLeft -= pdfHeight;
        position -= pdfHeight;
        page++;
      }

      // Add metadata
      pdf.setProperties({
        title: filename,
        subject: 'Honeypot Thesis Report',
        creator: 'Honeypot Dashboard',
      });

      // Save the PDF
      const timestamp = new Date().toISOString().slice(0, 10);
      pdf.save(`${filename}-${timestamp}.pdf`);
    } catch (error) {
      console.error('PDF export failed:', error);
    } finally {
      setExporting(false);
    }
  };

  return (
    <button
      onClick={handleExport}
      disabled={exporting}
      className={`flex items-center gap-2 px-4 py-2 bg-neon-green/20 text-neon-green rounded-lg hover:bg-neon-green/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${className}`}
    >
      {exporting ? (
        <>
          <Loader2 className="w-4 h-4 animate-spin" />
          <span>Exporting...</span>
        </>
      ) : (
        <>
          <Download className="w-4 h-4" />
          <span>{title}</span>
        </>
      )}
    </button>
  );
}

// Additional component for print button
export function PrintButton({ className = '' }: { className?: string }) {
  return (
    <button
      onClick={() => window.print()}
      className={`flex items-center gap-2 px-4 py-2 bg-bg-secondary text-text-secondary rounded-lg hover:text-text-primary transition-colors ${className}`}
    >
      <FileText className="w-4 h-4" />
      <span>Print</span>
    </button>
  );
}

