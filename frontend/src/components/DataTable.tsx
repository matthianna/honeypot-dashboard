import { ReactNode, useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react';
import LoadingSpinner from './LoadingSpinner';
import EmptyState from './EmptyState';

interface Column<T> {
  key: string;
  header: string;
  render?: (item: T, index: number) => ReactNode;
  className?: string;
  sortable?: boolean;
  sortKey?: string; // Use a different key for sorting than display
}

type SortDirection = 'asc' | 'desc' | null;

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  emptyMessage?: string;
  onRowClick?: (item: T) => void;
  maxHeight?: string;
  defaultSort?: { key: string; direction: SortDirection };
}

function getSortValue(item: Record<string, unknown>, key: string): string | number {
  const value = item[key];
  if (value === null || value === undefined) return '';
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    // Try to parse as number
    const num = parseFloat(value);
    if (!isNaN(num)) return num;
    return value.toLowerCase();
  }
  return String(value).toLowerCase();
}

export default function DataTable<T>({
  columns,
  data,
  loading = false,
  emptyMessage = 'No data available',
  onRowClick,
  maxHeight = '400px',
  defaultSort,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(defaultSort?.key || null);
  const [sortDirection, setSortDirection] = useState<SortDirection>(defaultSort?.direction || null);

  const handleSort = (column: Column<T>) => {
    if (!column.sortable) return;

    const key = column.sortKey || column.key;

    if (sortKey === key) {
      // Cycle through: asc -> desc -> none
      if (sortDirection === 'asc') {
        setSortDirection('desc');
      } else if (sortDirection === 'desc') {
        setSortDirection(null);
        setSortKey(null);
      } else {
        setSortDirection('asc');
      }
    } else {
      setSortKey(key);
      setSortDirection('asc');
    }
  };

  const sortedData = useMemo(() => {
    if (!sortKey || !sortDirection) return data;

    return [...data].sort((a, b) => {
      const aVal = getSortValue(a as Record<string, unknown>, sortKey);
      const bVal = getSortValue(b as Record<string, unknown>, sortKey);

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [data, sortKey, sortDirection]);

  const getSortIcon = (column: Column<T>) => {
    if (!column.sortable) return null;

    const key = column.sortKey || column.key;
    const isActive = sortKey === key;

    if (!isActive) {
      return <ChevronsUpDown className="w-3 h-3 ml-1 opacity-40" />;
    }

    return sortDirection === 'asc' ? (
      <ChevronUp className="w-3 h-3 ml-1 text-neon-green" />
    ) : (
      <ChevronDown className="w-3 h-3 ml-1 text-neon-green" />
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner />
      </div>
    );
  }

  if (data.length === 0) {
    return <EmptyState variant="no-data" description={emptyMessage} size="sm" />;
  }

  return (
    <div className="overflow-x-auto scrollbar-thin" style={{ maxHeight }}>
      <table className="w-full">
        <thead className="sticky top-0 bg-bg-card z-10">
          <tr className="border-b border-bg-hover">
            {columns.map((column) => (
              <th
                key={column.key}
                className={`px-4 py-3 text-left text-xs font-semibold text-text-secondary uppercase tracking-wider ${
                  column.sortable ? 'cursor-pointer select-none hover:text-text-primary transition-colors' : ''
                } ${column.className || ''}`}
                onClick={() => handleSort(column)}
              >
                <div className="flex items-center">
                  {column.header}
                  {getSortIcon(column)}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-bg-hover">
          {sortedData.map((item, index) => (
            <tr
              key={index}
              className={`table-row transition-colors ${
                onRowClick ? 'cursor-pointer hover:bg-bg-hover/50' : ''
              }`}
              onClick={() => onRowClick?.(item)}
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={`px-4 py-3 text-sm text-text-primary whitespace-nowrap ${column.className || ''}`}
                >
                  {column.render
                    ? column.render(item, index)
                    : String((item as Record<string, unknown>)[column.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
