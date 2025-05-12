'use client';
import { FaNetworkWired, FaGlobe } from "react-icons/fa";
import { MdSecurity } from "react-icons/md";

export default function Home() {
  return (
    <div
      className="bg-black h-screen bg-cover bg-center"
      style={{ backgroundImage: "url('/background.jpg')" }}
    >
      <div className="flex justify-end items-center h-full pr-10">
        <div className="text-white text-5xl text-center font-bold leading-snug uppercase">
          <p>
            Network Traffic <br />
            Monitoring System
          </p>
          <div className="flex justify-center space-x-4 mt-6">
            <FaNetworkWired className="text-blue-500 text-5xl" />
            <MdSecurity className="text-green-500 text-5xl" />
            <FaGlobe className="text-yellow-500 text-5xl" />
          </div>
        </div>
      </div>
    </div>
  );
}
