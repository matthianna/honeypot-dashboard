import { useState, useCallback, useEffect } from 'react';
import { FileText, Search, Terminal, Shield, Clock, Download, Printer } from 'lucide-react';
import { useAnalytics } from './AnalyticsLayout';
import DataTable from '../../components/DataTable';
import LoadingSpinner from '../../components/LoadingSpinner';
import IPLink from '../../components/IPLink';
import { useApiWithRefresh } from '../../hooks/useApi';
import api from '../../services/api';

const VARIANT_COLORS: Record<string, string> = {
  plain: '#39ff14',
  openai: '#00d4ff',
  ollama: '#ff6600',
};

export default function CaseStudy() {
  const { timeRange, setLastUpdated } = useAnalytics();
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [caseStudy, setCaseStudy] = useState<any>(null);
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseError, setCaseError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  const { data: sessionsList, loading: listLoading } = useApiWithRefresh(
    useCallback(() => api.getAnalyticsCaseStudyList(timeRange, 3, 30),
    [timeRange]),
    [timeRange],
    60000
  );

  useEffect(() => {
    if (sessionsList) setLastUpdated(new Date());
  }, [sessionsList, setLastUpdated]);

  const loadCaseStudy = async (sessionId: string) => {
    setSelectedSession(sessionId);
    setCaseLoading(true);
    setCaseStudy(null);
    setCaseError(null);
    try {
      const data = await api.getAnalyticsCaseStudy(sessionId);
      // Check if response contains error
      if (data.error) {
        console.error('Case study error:', data.error);
        setCaseError(data.error);
        setCaseStudy(null);
      } else {
        setCaseStudy(data);
      }
    } catch (error) {
      console.error('Failed to load case study:', error);
      setCaseError('Failed to load case study. Please try again.');
      setCaseStudy(null);
    } finally {
      setCaseLoading(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleExportPDF = async () => {
    if (!caseStudy) return;
    
    try {
      const html2canvas = (await import('html2canvas')).default;
      const jsPDF = (await import('jspdf')).default;
      
      const element = document.getElementById('case-study-report');
      if (!element) return;
      
      const canvas = await html2canvas(element, {
        backgroundColor: '#0d0d14',
        scale: 2,
      });
      
      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
      
      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
      pdf.save(`case_study_${selectedSession?.slice(0, 8)}_${new Date().toISOString().split('T')[0]}.pdf`);
    } catch (error) {
      console.error('PDF export failed:', error);
    }
  };

  const sessionColumns = [
    { key: 'session_id', header: 'Session', render: (item: any) => (
      <button
        onClick={() => loadCaseStudy(item.session_id)}
        className={`font-mono text-xs hover:underline ${
          selectedSession === item.session_id ? 'text-neon-green font-bold' : 'text-text-primary'
        }`}
      >
        {item.session_id.slice(0, 12)}...
      </button>
    )},
    { key: 'variant', header: 'Variant', render: (item: any) => (
      <span 
        className="px-2 py-0.5 rounded text-xs"
        style={{ 
          backgroundColor: `${VARIANT_COLORS[item.variant] || '#888'}20`,
          color: VARIANT_COLORS[item.variant] || '#888'
        }}
      >
        {item.variant}
      </span>
    )},
    { key: 'src_ip', header: 'Source IP', render: (item: any) => 
      item.src_ip ? <IPLink ip={item.src_ip} /> : '-'
    },
    { key: 'commands', header: 'Commands', render: (item: any) => (
      <span className="text-neon-green font-medium">{item.commands}</span>
    )},
    { key: 'duration', header: 'Duration', render: (item: any) => `${typeof item.duration === 'number' ? item.duration.toFixed(1) : '0'}s` },
  ];

  const filteredSessions = sessionsList?.sessions?.filter((s: any) => 
    !searchQuery || 
    s.session_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.src_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.variant?.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-display font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-neon-green" />
            Case Study Builder
          </h2>
          <p className="text-sm text-text-muted mt-1">
            Select a session to generate a thesis-ready case study report
          </p>
        </div>
        {caseStudy && (
          <div className="flex gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-2 px-4 py-2 bg-bg-card border border-bg-hover rounded-lg text-text-secondary hover:text-text-primary hover:border-neon-green/50 transition-colors"
            >
              <Printer className="w-4 h-4" />
              Print
            </button>
            <button
              onClick={handleExportPDF}
              className="flex items-center gap-2 px-4 py-2 bg-neon-green text-black rounded-lg font-medium hover:bg-neon-green/80 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export PDF
            </button>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Session Selector */}
        <div className="lg:col-span-1 space-y-4">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search sessions..."
              className="w-full pl-10 pr-4 py-2 bg-bg-card border border-bg-hover rounded-lg text-text-primary placeholder-text-muted focus:border-neon-green focus:outline-none text-sm"
            />
          </div>

          {/* Session List */}
          <div className="bg-bg-card rounded-xl border border-bg-hover">
            <div className="p-3 border-b border-bg-hover">
              <h3 className="font-medium text-white text-sm">
                Interactive Sessions ({filteredSessions.length})
              </h3>
            </div>
            <DataTable
              columns={sessionColumns}
              data={filteredSessions}
              loading={listLoading}
              maxHeight="500px"
            />
          </div>
        </div>

        {/* Case Study Report */}
        <div className="lg:col-span-2">
          {!selectedSession ? (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-8 h-full flex items-center justify-center">
              <div className="text-center">
                <FileText className="w-16 h-16 text-text-muted mx-auto mb-4" />
                <h3 className="text-lg font-medium text-text-primary mb-2">
                  Select a Session
                </h3>
                <p className="text-text-muted text-sm max-w-md">
                  Choose an interactive session from the list to generate a detailed case study
                  report suitable for thesis documentation.
                </p>
              </div>
            </div>
          ) : caseLoading ? (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-8 h-full flex items-center justify-center">
              <LoadingSpinner />
            </div>
          ) : caseError ? (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-8 h-full flex items-center justify-center">
              <div className="text-center">
                <FileText className="w-16 h-16 text-neon-red mx-auto mb-4" />
                <h3 className="text-lg font-medium text-text-primary mb-2">
                  Error Loading Case Study
                </h3>
                <p className="text-text-muted text-sm max-w-md">
                  {caseError}
                </p>
                <button
                  onClick={() => selectedSession && loadCaseStudy(selectedSession)}
                  className="mt-4 px-4 py-2 bg-neon-green/20 text-neon-green rounded-lg hover:bg-neon-green/30 transition-colors"
                >
                  Try Again
                </button>
              </div>
            </div>
          ) : caseStudy ? (
            <div id="case-study-report" className="bg-bg-card rounded-xl border border-bg-hover p-6 space-y-6 print:bg-white print:text-black">
              {/* Report Header */}
              <div className="border-b border-bg-hover pb-4 print:border-black">
                <h2 className="text-xl font-display font-bold text-white print:text-black">
                  Case Study Report
                </h2>
                <p className="text-sm text-text-muted print:text-gray-600">
                  Session: <span className="font-mono">{caseStudy.session_id}</span>
                </p>
                <p className="text-xs text-text-muted print:text-gray-600 mt-1">
                  Generated: {new Date(caseStudy.generated_at).toLocaleString()}
                </p>
              </div>

              {/* Session Metadata */}
              <div>
                <h3 className="font-medium text-white mb-3 flex items-center gap-2 print:text-black">
                  <Clock className="w-4 h-4" />
                  Session Metadata
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-bg-secondary p-3 rounded-lg print:bg-gray-100">
                    <div className="text-xs text-text-muted print:text-gray-600">Variant</div>
                    <div 
                      className="font-medium"
                      style={{ color: VARIANT_COLORS[caseStudy.variant] || '#888' }}
                    >
                      {caseStudy.variant}
                    </div>
                  </div>
                  <div className="bg-bg-secondary p-3 rounded-lg print:bg-gray-100">
                    <div className="text-xs text-text-muted print:text-gray-600">Source IP</div>
                    <div className="font-mono text-sm">{caseStudy.info?.src_ip || '-'}</div>
                  </div>
                  <div className="bg-bg-secondary p-3 rounded-lg print:bg-gray-100">
                    <div className="text-xs text-text-muted print:text-gray-600">Duration</div>
                    <div className="font-mono text-sm">{typeof caseStudy.info?.duration === 'number' ? caseStudy.info.duration.toFixed(1) : '0'}s</div>
                  </div>
                  <div className="bg-bg-secondary p-3 rounded-lg print:bg-gray-100">
                    <div className="text-xs text-text-muted print:text-gray-600">Total Events</div>
                    <div className="font-mono text-sm">{caseStudy.total_events}</div>
                  </div>
                </div>
              </div>

              {/* Credentials */}
              {caseStudy.credentials?.length > 0 && (
                <div>
                  <h3 className="font-medium text-white mb-3 print:text-black">
                    Authentication Attempts ({caseStudy.credentials.length})
                  </h3>
                  <div className="bg-bg-secondary rounded-lg overflow-hidden print:bg-gray-100">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-bg-hover print:border-gray-300">
                          <th className="text-left p-2 text-text-muted print:text-gray-600">Username</th>
                          <th className="text-left p-2 text-text-muted print:text-gray-600">Password</th>
                          <th className="text-left p-2 text-text-muted print:text-gray-600">Result</th>
                        </tr>
                      </thead>
                      <tbody>
                        {caseStudy.credentials.slice(0, 10).map((cred: any, i: number) => (
                          <tr key={i} className="border-b border-bg-hover/50 print:border-gray-200">
                            <td className="p-2 font-mono text-neon-green print:text-green-600">{cred.username}</td>
                            <td className="p-2 font-mono text-neon-orange print:text-orange-600">{cred.password}</td>
                            <td className="p-2">
                              <span className={cred.success ? 'text-neon-green print:text-green-600' : 'text-neon-red print:text-red-600'}>
                                {cred.success ? 'Success' : 'Failed'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Command Timeline */}
              {caseStudy.commands?.length > 0 && (
                <div>
                  <h3 className="font-medium text-white mb-3 flex items-center gap-2 print:text-black">
                    <Terminal className="w-4 h-4" />
                    Command Timeline ({caseStudy.commands.length} commands)
                  </h3>
                  <div className="bg-bg-secondary rounded-lg p-4 space-y-2 font-mono text-sm print:bg-gray-100">
                    {caseStudy.commands.map((cmd: any, i: number) => (
                      <div key={i} className="flex items-start gap-3">
                        <span className="text-xs text-text-muted whitespace-nowrap print:text-gray-600">
                          {new Date(cmd.timestamp).toLocaleTimeString()}
                        </span>
                        <span className="text-neon-green print:text-green-600">$ {cmd.command}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* MITRE Techniques */}
              {caseStudy.mitre_techniques?.length > 0 && (
                <div>
                  <h3 className="font-medium text-white mb-3 flex items-center gap-2 print:text-black">
                    <Shield className="w-4 h-4" />
                    MITRE ATT&CK Techniques Detected ({caseStudy.mitre_techniques.length})
                  </h3>
                  <div className="space-y-3">
                    {caseStudy.mitre_techniques.map((tech: any, i: number) => (
                      <div key={i} className="bg-bg-secondary rounded-lg p-3 print:bg-gray-100">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="font-mono text-neon-blue print:text-blue-600">{tech.id}</span>
                          <span className="font-medium">{tech.name}</span>
                          <span className="text-xs text-text-muted print:text-gray-600">({tech.tactic})</span>
                        </div>
                        <div className="text-xs text-text-muted print:text-gray-600">
                          Evidence: {tech.evidence?.slice(0, 3).map((e: string) => `"${e}"`).join(', ')}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-bg-card rounded-xl border border-bg-hover p-8 h-full flex items-center justify-center">
              <div className="text-center text-text-muted">
                Failed to load case study data
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

