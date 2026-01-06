/**
 * Utility functions for exporting data to CSV and JSON
 */

interface ExportOptions {
  filename: string;
  data: Record<string, unknown>[] | Record<string, unknown>;
}

/**
 * Flatten a nested object for CSV export
 */
function flattenObject(obj: Record<string, unknown>, prefix = ''): Record<string, string | number | boolean | null> {
  const result: Record<string, string | number | boolean | null> = {};
  
  for (const [key, value] of Object.entries(obj)) {
    const newKey = prefix ? `${prefix}_${key}` : key;
    
    if (value === null || value === undefined) {
      result[newKey] = null;
    } else if (typeof value === 'object' && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value as Record<string, unknown>, newKey));
    } else if (Array.isArray(value)) {
      result[newKey] = value.join('; ');
    } else {
      result[newKey] = value as string | number | boolean;
    }
  }
  
  return result;
}

/**
 * Convert array of objects to CSV string
 */
function arrayToCSV(data: Record<string, unknown>[]): string {
  if (data.length === 0) return '';
  
  // Flatten all objects and collect all keys
  const flattenedData = data.map(item => flattenObject(item));
  const allKeys = new Set<string>();
  flattenedData.forEach(item => Object.keys(item).forEach(key => allKeys.add(key)));
  const headers = Array.from(allKeys);
  
  // Build CSV rows
  const csvRows = [
    headers.join(','), // Header row
    ...flattenedData.map(item =>
      headers.map(header => {
        const value = item[header];
        if (value === null || value === undefined) return '';
        if (typeof value === 'string') {
          // Escape quotes and wrap in quotes if contains comma/newline
          const escaped = value.replace(/"/g, '""');
          return escaped.includes(',') || escaped.includes('\n') || escaped.includes('"')
            ? `"${escaped}"`
            : escaped;
        }
        return String(value);
      }).join(',')
    )
  ];
  
  return csvRows.join('\n');
}

/**
 * Download a file with the given content
 */
function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Export data as JSON file
 */
export function exportToJSON({ filename, data }: ExportOptions): void {
  const jsonString = JSON.stringify(data, null, 2);
  const fullFilename = filename.endsWith('.json') ? filename : `${filename}.json`;
  downloadFile(jsonString, fullFilename, 'application/json');
}

/**
 * Export data as CSV file
 */
export function exportToCSV({ filename, data }: ExportOptions): void {
  // Handle both array and single object
  const dataArray = Array.isArray(data) ? data : [data];
  const csvString = arrayToCSV(dataArray as Record<string, unknown>[]);
  const fullFilename = filename.endsWith('.csv') ? filename : `${filename}.csv`;
  downloadFile(csvString, fullFilename, 'text/csv');
}

/**
 * Format date for filename
 */
export function getExportFilename(base: string, timeRange?: string): string {
  const date = new Date().toISOString().slice(0, 10);
  const rangeStr = timeRange ? `_${timeRange}` : '';
  return `${base}${rangeStr}_${date}`;
}





