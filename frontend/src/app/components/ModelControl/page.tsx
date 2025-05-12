'use client';
import { useState } from 'react';
import { runModel } from '@/lib/api';

export default function ModelControl() {
  const [status, setStatus] = useState('');

  const handleRun = async (type: 'rf' | 'rl') => {
    setStatus(`Running ${type.toUpperCase()}...`);
    const res = await runModel(type);
    setStatus(res.success ? res.output : res.error);
  };

  return (
    <div className="bg-[#1e1e1e] flex flex-col md:flex-row items-center gap-6 rounded-xl shadow p-6 w-full h-full min-h-[220px]">
      <img
        src="/image.jpg"
        alt="System Preview"
        className="w-48 sm:w-64 md:w-80 h-48 object-cover rounded-lg shadow border border-gray-700"
      />

      <div className="flex flex-col gap-4 w-full">
        <button
          onClick={() => handleRun('rf')}
          className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-xl w-full"
        >
          Run Random Forest
        </button>
        <button
          onClick={() => handleRun('rl')}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl w-full"
        >
          Run Reinforcement Learning
        </button>
        <p className="text-sm text-gray-400">{status}</p>
      </div>
    </div>
  );
}