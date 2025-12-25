import { ReactNode, useState } from 'react';

interface Tab {
  id: string;
  label: string;
  icon?: ReactNode;
  content: ReactNode;
}

interface TabsProps {
  tabs: Tab[];
  defaultTab?: string;
  className?: string;
}

export default function Tabs({ tabs, defaultTab, className = '' }: TabsProps) {
  const [activeTab, setActiveTab] = useState(defaultTab || tabs[0]?.id);

  const currentTab = tabs.find((tab) => tab.id === activeTab);

  return (
    <div className={className}>
      {/* Tab Headers */}
      <div className="flex border-b border-bg-hover overflow-x-auto">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`
              flex items-center px-4 py-3 text-sm font-medium whitespace-nowrap
              border-b-2 transition-all duration-200
              ${
                activeTab === tab.id
                  ? 'border-neon-green text-neon-green'
                  : 'border-transparent text-text-secondary hover:text-text-primary hover:border-bg-hover'
              }
            `}
          >
            {tab.icon && <span className="mr-2">{tab.icon}</span>}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="py-4">{currentTab?.content}</div>
    </div>
  );
}

