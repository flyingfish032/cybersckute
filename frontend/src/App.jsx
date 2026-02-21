import React, { useState, useEffect, useRef } from 'react';
import LiveFeed from './components/LiveFeed';
import AttackMap from './components/AttackMap';
import ThreatChart from './components/ThreatChart';
import StatCard from './components/StatCard';
import CredentialsTable from './components/CredentialsTable';
import ServicesPanel from './components/ServicesPanel';
import AttackerProfile from './components/AttackerProfile';

function App() {
  const [stats, setStats] = useState({ attackers: 0, commands: 0, web_attacks: 0, credentials: 0, service_probes: 0 });
  const [logs, setLogs] = useState([]);
  const [attackers, setAttackers] = useState([]);
  const [selectedAttackerIp, setSelectedAttackerIp] = useState(null);
  const ws = useRef(null);

  const fetchAllData = () => {
    fetch('http://localhost:8000/api/attackers')
      .then(res => res.json()).then(data => setAttackers(data));
    fetch('http://localhost:8000/api/stats')
      .then(res => res.json()).then(data => setStats(data));
  };

  useEffect(() => {
    fetchAllData();

    ws.current = new WebSocket('ws://localhost:8000/live');
    ws.current.onopen = () => {
      setLogs(prev => [...prev, { ip: 'SYSTEM', message: 'CONNECTED TO SECURITY GRID', timestamp: Date.now() }]);
    };

    ws.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setLogs(prev => [...prev, { ...data, timestamp: Date.now() }]);

      if (data.type === 'command') {
        setStats(prev => ({ ...prev, commands: prev.commands + 1 }));
      } else if (data.type === 'web_attack') {
        setStats(prev => ({ ...prev, web_attacks: prev.web_attacks + 1 }));
      } else if (data.type === 'service_probe') {
        setStats(prev => ({ ...prev, service_probes: (prev.service_probes || 0) + 1 }));
        fetchAllData();
      } else if (data.type === 'login') {
        fetchAllData();
      }
    };

    return () => { if (ws.current) ws.current.close(); };
  }, []);

  const handleReset = async () => {
    if (window.confirm("Delete ALL honeypot data? This cannot be undone.")) {
      await fetch('http://localhost:8000/api/reset', { method: 'DELETE' });
      window.location.reload();
    }
  };

  const handleExport = async () => {
    const res = await fetch('http://localhost:8000/api/threat-intel/export');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intel_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen p-4 flex flex-col gap-4">
      {/* Header */}
      <header className="flex justify-between items-center border-b border-neon-green/30 pb-4 mb-2">
        <div>
          <h1 className="text-3xl font-bold glow-text tracking-widest text-neon-green">CYBER<span className="text-white">SENTINEL</span></h1>
          <p className="text-xs text-neon-blue tracking-widest">AI-POWERED ADAPTIVE HONEYPOT & THREAT INTELLIGENCE SYSTEM</p>
        </div>
        <div className="text-right flex items-center gap-3">
          <button
            onClick={handleExport}
            className="px-4 py-1.5 bg-blue-500/10 border border-blue-500/50 text-blue-400 text-xs font-bold rounded hover:bg-blue-500/20 transition-all uppercase tracking-wider"
          >
            ⬇ Export Intel
          </button>
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
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard title="Total Attackers" value={stats.attackers} color="text-neon-red" />
        <StatCard title="SSH Commands" value={stats.commands} color="text-neon-blue" />
        <StatCard title="Web Attacks" value={stats.web_attacks} color="text-yellow-400" />
        <StatCard title="Creds Stolen" value={stats.credentials} color="text-neon-green" />
        <StatCard title="Service Probes" value={stats.service_probes || 0} color="text-purple-400" />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-grow">
        {/* Left: Map & Charts */}
        <div className="lg:col-span-2 flex flex-col gap-6">
          <div>
            <h2 className="text-xs text-neon-green mb-1 uppercase tracking-wider">Global Threat Map</h2>
            <AttackMap attackers={attackers} />
          </div>
          <div>
            <h2 className="text-xs text-neon-green mb-1 uppercase tracking-wider">Attack Analytics</h2>
            <ThreatChart stats={stats} />
          </div>
          {/* Active Deceptions Panel */}
          <ServicesPanel />
        </div>

        {/* Right: Live Feed */}
        <div className="lg:col-span-1">
          <h2 className="text-xs text-neon-green mb-1 uppercase tracking-wider">Real-time Event Log</h2>
          <LiveFeed logs={logs} />
        </div>
      </div>

      {/* Attackers Table with Profile Button */}
      <div className="w-full">
        <h2 className="text-xs text-neon-green mb-2 uppercase tracking-wider">Known Attackers</h2>
        <div className="rounded border border-neon-green/20 bg-black/30 overflow-x-auto">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-neon-green/20 text-gray-500 uppercase tracking-wider">
                <th className="p-3 text-left">IP Address</th>
                <th className="p-3 text-left">Location</th>
                <th className="p-3 text-left">Risk Score</th>
                <th className="p-3 text-left">TTPs</th>
                <th className="p-3 text-left">Last Seen</th>
                <th className="p-3 text-left">Profile</th>
              </tr>
            </thead>
            <tbody>
              {attackers.length === 0 ? (
                <tr><td colSpan={6} className="p-6 text-center text-gray-600">No attackers recorded yet. Start an attack simulation.</td></tr>
              ) : attackers.map(a => (
                <tr key={a.id} className="border-b border-neon-green/10 hover:bg-neon-green/5 transition-colors">
                  <td className="p-3 text-neon-green font-bold">{a.ip_address}</td>
                  <td className="p-3 text-gray-400">{a.city || '?'}, {a.country || '?'}</td>
                  <td className="p-3">
                    <span className={`font-bold ${a.risk_score >= 75 ? 'text-red-400' : a.risk_score >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
                      {a.risk_score}/100
                    </span>
                  </td>
                  <td className="p-3 max-w-xs truncate text-purple-300">
                    {a.ttp_tags ? a.ttp_tags.split(',').filter(Boolean).length + ' TTPs' : '—'}
                  </td>
                  <td className="p-3 text-gray-500">{new Date(a.last_seen).toLocaleString()}</td>
                  <td className="p-3">
                    <button
                      onClick={() => setSelectedAttackerIp(a.ip_address)}
                      className="px-2 py-1 bg-neon-green/10 border border-neon-green/30 text-neon-green text-xs rounded hover:bg-neon-green/20 transition-all"
                    >
                      🔍 Profile
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Credentials Table */}
      <div className="w-full">
        <CredentialsTable />
      </div>

      {/* Attacker Profile Modal */}
      {selectedAttackerIp && (
        <AttackerProfile ip={selectedAttackerIp} onClose={() => setSelectedAttackerIp(null)} />
      )}
    </div>
  );
}

export default App;
