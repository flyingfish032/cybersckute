import React, { useState, useEffect } from 'react';

const SERVICE_COLORS = {
    mysql: { color: 'text-blue-400', border: 'border-blue-500/30', bg: 'bg-blue-500/10', icon: '🐬' },
    ftp: { color: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/10', icon: '📁' },
    http_alt: { color: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/10', icon: '🌐' },
};

function ServicesPanel() {
    const [services, setServices] = useState([]);
    const [loading, setLoading] = useState(false);

    const fetchServices = () => {
        fetch('http://localhost:8000/api/services')
            .then(r => r.json())
            .then(setServices)
            .catch(console.error);
    };

    useEffect(() => {
        fetchServices();
        const interval = setInterval(fetchServices, 5000);
        return () => clearInterval(interval);
    }, []);

    const spawnService = async (name) => {
        setLoading(true);
        await fetch(`http://localhost:8000/api/services/${name}/spawn`, { method: 'POST' });
        fetchServices();
        setLoading(false);
    };

    const stopService = async (name) => {
        setLoading(true);
        await fetch(`http://localhost:8000/api/services/${name}/stop`, { method: 'DELETE' });
        fetchServices();
        setLoading(false);
    };

    return (
        <div className="rounded border border-neon-green/20 bg-black/30 p-4">
            <div className="flex items-center justify-between mb-3">
                <h2 className="text-xs text-neon-green uppercase tracking-wider font-bold">
                    ⚡ Active Deceptions
                </h2>
                <span className="text-xs text-gray-500">{services.filter(s => s.is_running).length} / {services.length} running</span>
            </div>

            <div className="flex flex-col gap-2">
                {services.map((svc) => {
                    const style = SERVICE_COLORS[svc.name] || { color: 'text-gray-400', border: 'border-gray-600', bg: 'bg-gray-500/10', icon: '🔌' };
                    return (
                        <div
                            key={svc.name}
                            className={`flex items-center justify-between p-3 rounded border ${style.border} ${style.bg}`}
                        >
                            <div className="flex items-center gap-3">
                                <span className="text-lg">{style.icon}</span>
                                <div>
                                    <div className={`font-bold text-sm uppercase tracking-widest ${style.color}`}>
                                        {svc.name}
                                        <span className="ml-2 text-xs text-gray-500">:{svc.port}</span>
                                    </div>
                                    <div className="text-xs text-gray-500">{svc.description}</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                <div className="text-right">
                                    <div className={`text-xs font-bold ${svc.is_running ? 'text-neon-green' : 'text-gray-600'}`}>
                                        {svc.is_running ? '● LIVE' : '○ OFFLINE'}
                                    </div>
                                    <div className="text-xs text-gray-500">{svc.interaction_count || 0} probes</div>
                                </div>
                                {svc.is_running ? (
                                    <button
                                        onClick={() => stopService(svc.name)}
                                        disabled={loading}
                                        className="px-2 py-1 text-xs bg-red-500/10 border border-red-500/40 text-red-400 rounded hover:bg-red-500/20 transition-all"
                                    >
                                        STOP
                                    </button>
                                ) : (
                                    <button
                                        onClick={() => spawnService(svc.name)}
                                        disabled={loading}
                                        className="px-2 py-1 text-xs bg-neon-green/10 border border-neon-green/40 text-neon-green rounded hover:bg-neon-green/20 transition-all"
                                    >
                                        SPAWN
                                    </button>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export default ServicesPanel;
