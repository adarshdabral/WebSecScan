import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import axios from 'axios';
import { toast } from 'react-toastify';
import ScanResults from './ScanResults';

interface ScanOption {
  id: string;
  name: string;
  description: string;
  endpoint: string;
}

const scanOptions: ScanOption[] = [
  {
    id: 'basic',
    name: 'Basic Scan',
    description: 'Gather general information about the website',
    endpoint: '/basicscan',
  },
  {
    id: 'sql',
    name: 'SQL Injection Scan',
    description: 'Check for SQL injection vulnerabilities',
    endpoint: '/sqlscan',
  },
  {
    id: 'password',
    name: 'Weak Password Check',
    description: 'Test for common weak passwords',
    endpoint: '/password',
  },
  {
    id: 'stress',
    name: 'Website Stress Test',
    description: 'Test website resilience under load',
    endpoint: '/webstresser',
  },
  {
    id: 'xss',
    name: 'XSS Vulnerability Check',
    description: 'Check for Cross-Site Scripting vulnerabilities',
    endpoint: '/xss',
  },
  {
    id: 'deface',
    name: 'Deface Vulnerability Check',
    description: 'Check for potential defacement vulnerabilities',
    endpoint: '/deface',
  },
  {
    id: 'dns',
    name: 'DNS Records Check',
    description: 'Analyze DNS records and configurations',
    endpoint: '/dnsrecord',
  },
  {
    id: 'full',
    name: 'Full Comprehensive Scan',
    description: 'Run all security checks',
    endpoint: '/scanner/fullscan',
  },
];

const Scanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [selectedScans, setSelectedScans] = useState<string[]>([]);
  const [results, setResults] = useState<Record<string, any>>({});

  const scanMutation = useMutation({
    mutationFn: async ({ url, endpoint }: { url: string; endpoint: string }) => {
      const response = await axios.post(`http://localhost:10037${endpoint}`, {
        website: url,
      });
      return response.data;
    },
    onSuccess: (data, variables) => {
      setResults((prev) => ({
        ...prev,
        [variables.endpoint]: data,
      }));
      toast.success('Scan completed successfully!');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.error || 'Scan failed');
    },
  });

  const handleScan = async () => {
    if (!url) {
      toast.error('Please enter a URL');
      return;
    }

    if (selectedScans.length === 0) {
      toast.error('Please select at least one scan type');
      return;
    }

    setResults({});
    selectedScans.forEach((scanId) => {
      const scan = scanOptions.find((s) => s.id === scanId);
      if (scan) {
        scanMutation.mutate({ url, endpoint: scan.endpoint });
      }
    });
  };

  const toggleScan = (scanId: string) => {
    setSelectedScans((prev) =>
      prev.includes(scanId)
        ? prev.filter((id) => id !== scanId)
        : [...prev, scanId]
    );
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
          Website Security Scanner
        </h2>
        <div className="space-y-4">
          <div>
            <label
              htmlFor="url"
              className="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >
              Website URL
            </label>
            <input
              type="url"
              id="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com"
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-primary-500 focus:ring-primary-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {scanOptions.map((scan) => (
              <div
                key={scan.id}
                className={`p-4 rounded-lg border cursor-pointer transition-colors ${
                  selectedScans.includes(scan.id)
                    ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                    : 'border-gray-200 dark:border-gray-700 hover:border-primary-300 dark:hover:border-primary-700'
                }`}
                onClick={() => toggleScan(scan.id)}
              >
                <h3 className="font-medium text-gray-900 dark:text-white">
                  {scan.name}
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {scan.description}
                </p>
              </div>
            ))}
          </div>

          <button
            onClick={handleScan}
            disabled={scanMutation.isPending}
            className="w-full bg-primary-600 text-white py-2 px-4 rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {scanMutation.isPending ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </div>

      {Object.keys(results).length > 0 && (
        <ScanResults results={results} scanOptions={scanOptions} />
      )}
    </div>
  );
};

export default Scanner; 