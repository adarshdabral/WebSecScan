import React, { useState } from 'react';
import { ChevronDownIcon, ChevronUpIcon } from '@heroicons/react/24/outline';

interface ScanResultProps {
  results: Record<string, any>;
  scanOptions: Array<{
    id: string;
    name: string;
    description: string;
    endpoint: string;
  }>;
}

const ScanResults: React.FC<ScanResultProps> = ({ results, scanOptions }) => {
  const [expandedSections, setExpandedSections] = useState<string[]>([]);

  const toggleSection = (endpoint: string) => {
    setExpandedSections((prev) =>
      prev.includes(endpoint)
        ? prev.filter((e) => e !== endpoint)
        : [...prev, endpoint]
    );
  };

  const formatResult = (result: any): string => {
    if (Array.isArray(result)) {
      return result.join('\n');
    }
    if (typeof result === 'object') {
      return JSON.stringify(result, null, 2);
    }
    return String(result);
  };

  const getStatusColor = (result: any): string => {
    if (Array.isArray(result) && result.length === 0) {
      return 'text-green-500';
    }
    if (typeof result === 'string' && result.includes('Secure')) {
      return 'text-green-500';
    }
    if (typeof result === 'string' && result.includes('vulnerable')) {
      return 'text-red-500';
    }
    return 'text-yellow-500';
  };

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
        Scan Results
      </h2>
      {Object.entries(results).map(([endpoint, result]) => {
        const scanOption = scanOptions.find((s) => s.endpoint === endpoint);
        if (!scanOption) return null;

        const isExpanded = expandedSections.includes(endpoint);
        const statusColor = getStatusColor(result);

        return (
          <div
            key={endpoint}
            className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden"
          >
            <button
              onClick={() => toggleSection(endpoint)}
              className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              <div className="flex items-center space-x-3">
                <span className={`text-lg font-medium ${statusColor}`}>
                  {scanOption.name}
                </span>
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  {scanOption.description}
                </span>
              </div>
              {isExpanded ? (
                <ChevronUpIcon className="h-5 w-5 text-gray-500" />
              ) : (
                <ChevronDownIcon className="h-5 w-5 text-gray-500" />
              )}
            </button>
            {isExpanded && (
              <div className="px-4 py-3 bg-gray-50 dark:bg-gray-700">
                <pre className="whitespace-pre-wrap text-sm text-gray-700 dark:text-gray-300">
                  {formatResult(result)}
                </pre>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default ScanResults; 