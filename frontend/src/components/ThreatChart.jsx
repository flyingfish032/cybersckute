import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const ThreatChart = ({ stats }) => {

    // Fallback data if stats empty
    const data = [
        { name: 'SSH', count: stats.commands || 0, fill: '#00ff41' },
        { name: 'Web', count: stats.web_attacks || 0, fill: '#00f3ff' },
    ];

    const pieData = [
        { name: 'Low Risk', value: 400 },
        { name: 'High Risk', value: 100 },
    ];
    const COLORS = ['#00ff41', '#ff0033'];

    return (
        <div className='grid grid-cols-2 gap-4 h-64'>
            <div className="bg-hacker-black/50 border border-neon-green/20 p-2 rounded">
                <h3 className="text-neon-green text-sm mb-2 text-center">ATTACK VECTORS</h3>
                <ResponsiveContainer width="100%" height="90%">
                    <BarChart data={data}>
                        <XAxis dataKey="name" stroke="#00ff41" />
                        <YAxis stroke="#00ff41" />
                        <Tooltip contentStyle={{ backgroundColor: '#0b0f19', border: '1px solid #00ff41' }} />
                        <Bar dataKey="count" />
                    </BarChart>
                </ResponsiveContainer>
            </div>

            {/* Placeholder for Severity Distribution */}
            <div className="bg-hacker-black/50 border border-neon-green/20 p-2 rounded flex flex-col items-center justify-center">
                <h3 className="text-neon-green text-sm mb-2 text-center">SYSTEM STATUS</h3>
                <div className="text-4xl font-bold text-neon-green animate-pulse">ONLINE</div>
                <div className="text-xs text-gray-400 mt-2">MONITORING ACTIVE</div>
            </div>
        </div>
    );
};

export default ThreatChart;
