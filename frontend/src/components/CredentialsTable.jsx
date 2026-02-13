import { useState, useEffect } from 'react';
import { Shield, Key, Terminal, Globe } from 'lucide-react';

const CredentialsTable = () => {
    const [creds, setCreds] = useState([]);

    useEffect(() => {
        const fetchCreds = async () => {
            try {
                const res = await fetch('http://localhost:8000/api/credentials');
                const data = await res.json();
                setCreds(data);
            } catch (error) {
                console.error("Error fetching credentials:", error);
            }
        };

        fetchCreds();
        // Poll every 5 seconds
        const interval = setInterval(fetchCreds, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="bg-slate-900/50 backdrop-blur-sm border border-slate-700/50 rounded-xl p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-6">
                <div className="p-2 bg-red-500/10 rounded-lg">
                    <Key className="w-6 h-6 text-red-400" />
                </div>
                <h2 className="text-xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">
                    Stolen Credentials
                </h2>
                <span className="ml-auto px-3 py-1 text-xs font-mono bg-slate-800 rounded-full text-slate-400 border border-slate-700">
                    {creds.length} CAPTURED
                </span>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-left">
                    <thead>
                        <tr className="border-b border-slate-700/50 text-slate-400 text-sm">
                            <th className="pb-3 pl-4 font-medium">TIMESTAMP</th>
                            <th className="pb-3 font-medium">SOURCE</th>
                            <th className="pb-3 font-medium">ATTACKER IP</th>
                            <th className="pb-3 font-medium">USERNAME</th>
                            <th className="pb-3 pr-4 font-medium">PASSWORD</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/30">
                        {creds.map((cred) => (
                            <tr key={cred.id} className="group hover:bg-slate-800/30 transition-colors">
                                <td className="py-3 pl-4 text-xs font-mono text-slate-500">
                                    {new Date(cred.timestamp).toLocaleTimeString()}
                                </td>
                                <td className="py-3">
                                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${cred.source === 'ssh'
                                        ? 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                                        : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                        }`}>
                                        {cred.source === 'ssh' ? <Terminal size={10} /> : <Globe size={10} />}
                                        {cred.source.toUpperCase()}
                                    </span>
                                </td>
                                <td className="py-3 text-sm font-mono text-slate-300">
                                    {cred.attacker_ip}
                                </td>
                                <td className="py-3 text-sm text-yellow-400/90 font-mono max-w-[200px] truncate" title={cred.username}>
                                    {cred.username}
                                </td>
                                <td className="py-3 pr-4 text-sm text-red-400/90 font-mono max-w-[200px] truncate" title={cred.password}>
                                    {cred.password}
                                </td>
                            </tr>
                        ))}
                        {creds.length === 0 && (
                            <tr>
                                <td colSpan="5" className="py-8 text-center text-slate-500 italic">
                                    No credentials captured yet...
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};

export default CredentialsTable;
