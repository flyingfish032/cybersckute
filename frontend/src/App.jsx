import React, { useState, useEffect, useRef } from 'react';
import LiveFeed from './components/LiveFeed';
import AttackMap from './components/AttackMap';
import ThreatChart from './components/ThreatChart';
import StatCard from './components/StatCard';
import CredentialsTable from './components/CredentialsTable';

function App() {
  const [stats, setStats] = useState({ attackers: 0, commands: 0, web_attacks: 0, credentials: 0 });
  const [logs, setLogs] = useState([]);
  const [attackers, setAttackers] = useState([]);
  const ws = useRef(null);

  useEffect(() => {
    // Initial Fetch
    fetch('http://localhost:8000/api/attackers')
      .then(res => res.json())
      .then(data => setAttackers(data));

    fetch('http://localhost:8000/api/stats')
      .then(res => res.json())
      .then(data => setStats(data));

    // WebSocket Connection
    ws.current = new WebSocket('ws://localhost:8000/live');

    ws.current.onopen = () => {
      console.log('Connected to Honeypot Live Feed');
      setLogs(prev => [...prev, { ip: 'SYSTEM', message: 'CONNECTED TO SECURITY GRID', timestamp: Date.now() }]);
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log('New Event:', data);

      // Update Logs
      setLogs(prev => [...prev, { ...data, timestamp: Date.now() }]);

      // Update Stats (optimistic)
      if (data.type === 'command') {
        setStats(prev => ({ ...prev, commands: prev.commands + 1 }));
      } else if (data.type === 'web_attack') {
        setStats(prev => ({ ...prev, web_attacks: prev.web_attacks + 1 }));
      } else if (data.type === 'login') {
        // Refresh attackers list if new login
        fetch('http://localhost:8000/api/attackers').then(res => res.json()).then(setAttackers);
      }
    };

    return () => {
      if (ws.current) ws.current.close();
    };
  }, []);

  const handleReset = async () => {
    if (window.confirm("Are you sure you want to delete ALL data? This cannot be undone.")) {
      await fetch('http://localhost:8000/api/reset', { method: 'DELETE' });
      window.location.reload();
    }
  };

  return (
    <div className="min-h-screen p-4 flex flex-col gap-4">
      {/* Header */}
      <header className="flex justify-between items-center border-b border-neon-green/30 pb-4 mb-2">
        <div>
          <h1 className="text-3xl font-bold glow-text tracking-widest text-neon-green">CYBER<span className="text-white">SENTINEL</span></h1>
          <p className="text-xs text-neon-blue tracking-widest">AI-POWERED THREAT INTELLIGENCE SYSTEM</p>
        </div>
        <div className="text-right flex items-center gap-4">
          <button
            onClick={handleReset}
            className="px-4 py-1.5 bg-red-500/10 border border-red-500/50 text-red-400 text-xs font-bold rounded hover:bg-red-500/20 transition-all uppercase tracking-wider"
          >
            Reset Data
          </button>
          <div>
            <div className="text-xs text-gray-500">SYSTEM STATUS</div>
            <div className="text-neon-green font-bold animate-pulse">LIVE MONITORING</div>
          </div>
        </div>
      </header>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard title="Total Attackers" value={stats.attackers} color="text-neon-red" />
        <StatCard title="SSH Commands" value={stats.commands} color="text-neon-blue" />
        <StatCard title="Web Attacks" value={stats.web_attacks} color="text-yellow-400" />
        <StatCard title="Credentials Stolen" value={stats.credentials} color="text-neon-green" />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-full flex-grow">

        {/* Left Column: Map & Charts */}
        <div className="lg:col-span-2 flex flex-col gap-6">
          <div className="relative">
            <h2 className="text-xs text-neon-green mb-1 uppercase tracking-wider">Global Threat Map</h2>
            <AttackMap attackers={attackers} />
          </div>
          <div>
            <h2 className="text-xs text-neon-green mb-1 uppercase tracking-wider">Attack Analytics</h2>
            <ThreatChart stats={stats} />
          </div>
        </div>

        {/* Right Column: Live Feed */}
        <div className="lg:col-span-1">
          <h2 className="text-xs text-neon-green mb-1 uppercase tracking-wider">Real-time Event Log</h2>
          <LiveFeed logs={logs} />
        </div>
      </div>

      {/* Credentials Table */}
      <div className="w-full">
        <CredentialsTable />
      </div>
    </div>
  );
}

export default App;
