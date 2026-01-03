import { Routes, Route } from 'react-router-dom';
import AnalyticsLayout from './AnalyticsLayout';
import Overview from './Overview';
import Health from './Health';
import Timeline from './Timeline';
import Credentials from './Credentials';
import CowrieSessions from './CowrieSessions';
import Commands from './Commands';
import Mitre from './Mitre';
import WebPatterns from './WebPatterns';
import Malware from './Malware';
import RdpOverview from './RdpOverview';
import AiPerformance from './AiPerformance';
import CaseStudy from './CaseStudy';
// Firewall Analytics
import FirewallPressure from './FirewallPressure';
import FirewallClosedPorts from './FirewallClosedPorts';
import FirewallRules from './FirewallRules';
import FirewallTopAttackers from './FirewallTopAttackers';
import FirewallScanners from './FirewallScanners';
import FirewallCorrelation from './FirewallCorrelation';
// Galah
import GalahConversations from './GalahConversations';

export default function Analytics() {
  return (
    <Routes>
      <Route element={<AnalyticsLayout />}>
        <Route index element={<Overview />} />
        <Route path="health" element={<Health />} />
        <Route path="timeline" element={<Timeline />} />
        <Route path="credentials" element={<Credentials />} />
        <Route path="cowrie-sessions" element={<CowrieSessions />} />
        <Route path="commands" element={<Commands />} />
        <Route path="mitre" element={<Mitre />} />
        <Route path="web" element={<WebPatterns />} />
        <Route path="malware" element={<Malware />} />
        <Route path="rdp" element={<RdpOverview />} />
        <Route path="ai-performance" element={<AiPerformance />} />
        <Route path="case-study" element={<CaseStudy />} />
        {/* Firewall Analytics */}
        <Route path="firewall" element={<FirewallPressure />} />
        <Route path="firewall/closed-ports" element={<FirewallClosedPorts />} />
        <Route path="firewall/rules" element={<FirewallRules />} />
        <Route path="firewall/attackers" element={<FirewallTopAttackers />} />
        <Route path="firewall/scanners" element={<FirewallScanners />} />
        <Route path="firewall/correlation" element={<FirewallCorrelation />} />
        {/* Galah */}
        <Route path="galah-conversations" element={<GalahConversations />} />
      </Route>
    </Routes>
  );
}

