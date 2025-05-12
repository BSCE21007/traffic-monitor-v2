'use client';
import { useEffect, useState } from 'react';
import { fetchLogs } from '@/lib/api';

export default function LogsTable() {
  const [logs, setLogs] = useState<string[][]>([]);

  useEffect(() => {
    fetchLogs().then(raw => {
      const parsed = raw.map(line => line.trim().split(','));
      setLogs(parsed.slice(1));
    });
  }, []);

  return (
    <div className="mx-6 overflow-y-auto border border-[#333] rounded-lg">
      <table className="table-auto w-full text-sm">
        <thead>
          <tr className="bg-[#1e1e1e] text-gray-300">
            <th className="p-2 border border-[#333]">Time</th>
            <th className="p-2 border border-[#333]">IP</th>
            <th className="p-2 border border-[#333]">Type</th>
            <th className="p-2 border border-[#333]">Action</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log, i) => (
            <tr key={i} className="text-center even:bg-[#121212] odd:bg-[#181818] text-gray-200">
              {log.map((cell, j) => (
                <td key={j} className="p-2 border border-[#333]">{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}