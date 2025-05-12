'use client';
import { useEffect, useState } from 'react';
import { fetchLogs } from '@/lib/api';
import Image from 'next/image';

export default function AttackStats() {
  const [total, setTotal] = useState(0);

  useEffect(() => {
    fetchLogs().then(logs => setTotal(logs.length - 1));
  }, []);

  return (
    <div className="bg-[#1e1e1e] flex flex-col sm:flex-row items-center sm:items-start gap-4 rounded-xl shadow p-6 w-full h-full min-h-[220px]">
      <Image
        src="/lock.png"
        alt="Lock Icon"
        width={180} 
        height={180} 
        className="rounded w-32 sm:w-40 md:w-55" 
      />
      <div className="text-center sm:text-left">
        <h2 className="text-lg sm:text-xl md:text-2xl font-bold text-gray-300">ATTACKS STOPPED</h2>
        <p className="text-2xl sm:text-3xl font-bold text-green-500 mt-2">{total}</p>
      </div>
    </div>
  );
}