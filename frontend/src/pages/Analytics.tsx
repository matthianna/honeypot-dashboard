import { Map, BarChart2, Globe, TrendingUp, Activity, MapPin } from 'lucide-react';
import { 
  GlobalAttackHeatmap, 
  HoneypotAttackMaps, 
  CombinedHoneypotMap,
  AttackTrendMap 
} from '../components/CountryAttackMaps';
import AttackTimeline from '../components/AttackTimeline';
import LeafletGeoMap from '../components/LeafletGeoMap';
import Tabs from '../components/Tabs';

export default function Analytics() {
  const tabs = [
    {
      id: 'timeline',
      label: 'Attack Timeline',
      icon: <Activity className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <AttackTimeline />
          <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
            <h4 className="font-display font-bold text-text-primary mb-3">Understanding the Timeline</h4>
            <p className="text-text-secondary text-sm">
              This interactive timeline shows attack activity across all your honeypots over time. 
              Click on the honeypot cards above the chart to toggle their visibility. 
              The stacked area chart helps you understand attack patterns and which services are being targeted most frequently.
              Use the time range selector to zoom in on specific periods.
            </p>
          </div>
        </div>
      ),
    },
    {
      id: 'interactive',
      label: 'Interactive Map',
      icon: <MapPin className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <LeafletGeoMap />
          <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
            <h4 className="font-display font-bold text-text-primary mb-3">Interactive Attack Map</h4>
            <p className="text-text-secondary text-sm">
              This zoomable map shows attack origins with circle markers. The circle size represents the attack count from each country.
              Use the layer switcher (top right) to change between Dark, Street, Satellite, and Terrain views.
              Filter by honeypot type to see which services are being targeted from each region.
              Hover over any circle to see detailed attack breakdown.
            </p>
          </div>
        </div>
      ),
    },
    {
      id: 'global',
      label: 'Global Heatmap',
      icon: <Globe className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <GlobalAttackHeatmap />
          <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
            <h4 className="font-display font-bold text-text-primary mb-3">About This Map</h4>
            <p className="text-text-secondary text-sm">
              This heatmap shows the global distribution of all attacks detected by your honeypot network over the last 30 days. 
              Countries are colored based on attack intensity - darker shades indicate higher attack volumes.
              Hover over any country to see the exact attack count and percentage of total attacks.
            </p>
          </div>
        </div>
      ),
    },
    {
      id: 'honeypots',
      label: 'By Honeypot',
      icon: <BarChart2 className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <HoneypotAttackMaps />
          <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
            <h4 className="font-display font-bold text-text-primary mb-3">Honeypot Attack Sources</h4>
            <p className="text-text-secondary text-sm">
              Select a honeypot to see where its attacks originate from. Each honeypot attracts different types of attackers
              based on the services it emulates. SSH honeypots (Cowrie) often see different attack patterns than HTTP honeypots (Galah).
            </p>
          </div>
        </div>
      ),
    },
    {
      id: 'combined',
      label: 'Combined View',
      icon: <Map className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <CombinedHoneypotMap />
          <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
            <h4 className="font-display font-bold text-text-primary mb-3">Multi-Honeypot Analysis</h4>
            <p className="text-text-secondary text-sm">
              This view shows combined attack data from all honeypots. Hover over any country to see a breakdown of attacks
              by honeypot type, helping you understand which services are being targeted from each region.
            </p>
          </div>
        </div>
      ),
    },
    {
      id: 'trends',
      label: 'Weekly Trends',
      icon: <TrendingUp className="w-4 h-4" />,
      content: (
        <div className="space-y-6">
          <AttackTrendMap />
          <div className="bg-bg-secondary rounded-xl border border-bg-hover p-4">
            <h4 className="font-display font-bold text-text-primary mb-3">Recent Attack Trends</h4>
            <p className="text-text-secondary text-sm">
              This map shows attack activity from the last 7 days, highlighting recent trends in attack sources.
              Compare this with the 30-day heatmap to identify emerging attack patterns or changes in attacker behavior.
            </p>
          </div>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-neon-purple/20 rounded-lg">
          <Globe className="w-6 h-6 text-neon-purple" />
        </div>
        <div>
          <h1 className="text-2xl font-display font-bold text-text-primary">Geographic Analytics</h1>
          <p className="text-text-secondary">Analyze attack origins by country and honeypot</p>
        </div>
      </div>

      <Tabs tabs={tabs} />
    </div>
  );
}



