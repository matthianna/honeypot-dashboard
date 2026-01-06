import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import Card, { CardHeader, CardContent } from './Card';
import LoadingSpinner from './LoadingSpinner';

// Default port colors
const PORT_COLORS: Record<number, string> = {
  21: '#ff6600',   // FTP
  22: '#39ff14',   // SSH
  23: '#00d4ff',   // Telnet
  25: '#ff3366',   // SMTP
  80: '#ffd700',   // HTTP
  110: '#bf00ff',  // POP3
  143: '#00ff88',  // IMAP
  443: '#00ffff',  // HTTPS
  445: '#ff4500',  // SMB
  1433: '#9400d3', // MSSQL
  3306: '#00ced1', // MySQL
  3389: '#ff1493', // RDP
  5060: '#32cd32', // SIP
  5432: '#ff8c00', // PostgreSQL
  5900: '#8b0000', // VNC
  6379: '#4169e1', // Redis
  8080: '#ffa500', // HTTP Alt
  27017: '#20b2aa', // MongoDB
};

// Generate color for unknown ports
const getPortColor = (port: number, index: number): string => {
  if (PORT_COLORS[port]) return PORT_COLORS[port];
  const colors = ['#39ff14', '#00d4ff', '#ff6600', '#bf00ff', '#ff3366', '#ffd700'];
  return colors[index % colors.length];
};

// Common port names
const PORT_NAMES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  1433: 'MSSQL',
  3306: 'MySQL',
  3389: 'RDP',
  5060: 'SIP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  27017: 'MongoDB',
};

interface PortData {
  port: number;
  count: number;
  unique_ips?: number;
}

interface PortDistributionProps {
  data: PortData[];
  title?: string;
  loading?: boolean;
  showBarChart?: boolean;
  showPieChart?: boolean;
  showTable?: boolean;
  accentColor?: string;
}

export default function PortDistribution({
  data,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  title: _title = 'Port Distribution',
  loading = false,
  showBarChart = true,
  showPieChart = true,
  showTable = true,
  accentColor = '#39ff14',
}: PortDistributionProps) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner />
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-text-muted">
        No port data available
      </div>
    );
  }

  const totalEvents = data.reduce((sum, d) => sum + d.count, 0);
  
  // Prepare data with colors and labels
  const chartData = data.map((item, index) => ({
    ...item,
    name: `${item.port} (${PORT_NAMES[item.port] || 'Unknown'})`,
    shortName: PORT_NAMES[item.port] || String(item.port),
    color: getPortColor(item.port, index),
    percentage: ((item.count / totalEvents) * 100).toFixed(1),
  }));

  // Top 8 for pie chart
  const pieData = chartData.slice(0, 8);
  const otherCount = chartData.slice(8).reduce((sum, d) => sum + d.count, 0);
  if (otherCount > 0) {
    pieData.push({
      port: -1,
      count: otherCount,
      name: 'Other',
      shortName: 'Other',
      color: '#666',
      percentage: ((otherCount / totalEvents) * 100).toFixed(1),
    });
  }

  return (
    <div className="space-y-6">
      {/* Charts Row */}
      <div className={`grid gap-6 ${showBarChart && showPieChart ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
        {/* Bar Chart */}
        {showBarChart && (
          <Card>
            <CardHeader title="Events by Port" subtitle="Top targeted ports" />
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData.slice(0, 10)} layout="vertical">
                    <XAxis type="number" stroke="#666" tick={{ fill: '#888', fontSize: 11 }} />
                    <YAxis
                      type="category"
                      dataKey="shortName"
                      stroke="#666"
                      tick={{ fill: '#888', fontSize: 11 }}
                      width={70}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(26, 26, 37, 0.95)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                      }}
                      labelStyle={{ color: '#fff' }}
                      formatter={(value: number, _name: string, props: any) => [
                        `${value.toLocaleString()} (${props.payload.percentage}%)`,
                        'Events',
                      ]}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {chartData.slice(0, 10).map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Pie Chart */}
        {showPieChart && (
          <Card>
            <CardHeader title="Port Share" subtitle="Distribution of traffic" />
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={80}
                      paddingAngle={2}
                      dataKey="count"
                      nameKey="shortName"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: 'rgba(26, 26, 37, 0.95)',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px',
                      }}
                      labelStyle={{ color: '#fff' }}
                      formatter={(value: number, _name: string, props: any) => [
                        `${value.toLocaleString()} (${props.payload.percentage}%)`,
                        props.payload.name,
                      ]}
                    />
                    <Legend
                      verticalAlign="middle"
                      align="right"
                      layout="vertical"
                      wrapperStyle={{ paddingLeft: 20, fontSize: 11 }}
                      formatter={(value) => <span className="text-text-secondary">{value}</span>}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Table */}
      {showTable && (
        <Card>
          <CardHeader title="Port Details" subtitle="All targeted ports with statistics" />
          <CardContent className="p-0">
            <div className="max-h-[400px] overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-bg-card">
                  <tr className="border-b border-bg-hover">
                    <th className="px-4 py-3 text-left text-xs font-semibold text-text-secondary uppercase">Port</th>
                    <th className="px-4 py-3 text-left text-xs font-semibold text-text-secondary uppercase">Service</th>
                    <th className="px-4 py-3 text-right text-xs font-semibold text-text-secondary uppercase">Events</th>
                    <th className="px-4 py-3 text-right text-xs font-semibold text-text-secondary uppercase">Share</th>
                    {data[0]?.unique_ips !== undefined && (
                      <th className="px-4 py-3 text-right text-xs font-semibold text-text-secondary uppercase">Unique IPs</th>
                    )}
                  </tr>
                </thead>
                <tbody className="divide-y divide-bg-hover">
                  {chartData.map((item) => (
                    <tr key={item.port} className="hover:bg-bg-hover/50">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div
                            className="w-3 h-3 rounded-full"
                            style={{ backgroundColor: item.color }}
                          />
                          <span className="font-mono text-sm" style={{ color: item.color }}>
                            {item.port}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-text-secondary">
                        {PORT_NAMES[item.port] || 'Unknown'}
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-sm text-text-primary">
                        {item.count.toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <div className="w-16 h-2 bg-bg-hover rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${item.percentage}%`,
                                backgroundColor: item.color,
                              }}
                            />
                          </div>
                          <span className="text-xs text-text-muted w-12 text-right">
                            {item.percentage}%
                          </span>
                        </div>
                      </td>
                      {item.unique_ips !== undefined && (
                        <td className="px-4 py-3 text-right font-mono text-sm text-neon-blue">
                          {item.unique_ips?.toLocaleString() || 0}
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
                <tfoot className="bg-bg-card border-t border-bg-hover">
                  <tr>
                    <td colSpan={2} className="px-4 py-3 text-sm font-bold text-text-primary">
                      Total
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-sm font-bold" style={{ color: accentColor }}>
                      {totalEvents.toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-right text-xs text-text-muted">100%</td>
                    {data[0]?.unique_ips !== undefined && (
                      <td className="px-4 py-3 text-right font-mono text-sm font-bold text-neon-blue">
                        {data.reduce((sum, d) => sum + (d.unique_ips || 0), 0).toLocaleString()}
                      </td>
                    )}
                  </tr>
                </tfoot>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

