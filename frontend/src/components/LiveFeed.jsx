import React, { useEffect, useRef } from 'react';

const LiveFeed = ({ logs }) => {
    const bottomRef = useRef(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    return (
        <div className="bg-hacker-black border border-neon-green/30 p-4 h-96 overflow-y-auto font-mono text-xs rounded shadow-lg glow-box relative">
            <div className="absolute top-0 right-0 p-1 text-neon-green text-xs opacity-50">LIVE_FEED</div>
            {logs.map((log, index) => (
                <div key={index} className="mb-1 border-b border-neon-green/10 pb-1">
                    <span className="text-gray-500">[{new Date(log.timestamp || Date.now()).toLocaleTimeString()}]</span>
                    <span className="text-neon-blue mx-2">{log.ip}</span>
                    <span className={log.severity === 'CRITICAL' ? 'text-neon-red font-bold animate-pulse' : 'text-neon-green'}>
                        {log.message || log.command || log.payload || (log.username ? `Login Attempt: ${log.username}:${log.password}` : "Connection Established")}
                    </span>
                    {log.analysis && (
                        <div className="ml-8 text-xs text-gray-400">
                            Risk: <span className={log.analysis.score > 50 ? "text-neon-red" : "text-yellow-500"}>{log.analysis.score}</span> | {log.analysis.description}
                        </div>
                    )}
                </div>
            ))}
            <div ref={bottomRef} />
        </div>
    );
};

export default LiveFeed;
