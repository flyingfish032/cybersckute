import React from 'react';

const StatCard = ({ title, value, color = "text-neon-green" }) => {
    return (
        <div className="bg-hacker-black border border-neon-green/30 p-4 rounded glow-box flex flex-col items-center justify-center">
            <h3 className="text-gray-400 text-xs uppercase tracking-wider">{title}</h3>
            <p className={`text-3xl font-bold ${color} font-mono mt-2`}>{value}</p>
        </div>
    );
};

export default StatCard;
