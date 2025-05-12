'use client';
import Link from 'next/link';
import { AiFillHome } from 'react-icons/ai';
import { MdDashboard } from 'react-icons/md';
import { FaClipboardList } from 'react-icons/fa';

export default function Navbar() {
  return (
    <nav className="bg-black backdrop-blur-md border border-[#222] px-6 py-4 flex justify-center items-center space-x-6 rounded-lg shadow-md">
      <Link href="/" className="text-white hover:text-white font-bold text-lg flex items-center space-x-2">
        <AiFillHome className="text-blue-500" /> <span>HOME</span>
      </Link>
      <Link href="/dashboard" className="text-white hover:text-white font-bold text-lg flex items-center space-x-2">
        <MdDashboard className="text-green-500" /> <span>DASHBOARD</span>
      </Link>
      <Link href="/logs" className="text-white hover:text-white font-bold text-lg flex items-center space-x-2">
        <FaClipboardList className="text-yellow-500" /> <span>LOGS</span>
      </Link>
    </nav>
  );
}