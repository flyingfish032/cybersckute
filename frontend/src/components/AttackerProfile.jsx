import React, { useState } from 'react';
import {
    Document, Packer, Paragraph, TextRun, HeadingLevel,
    AlignmentType, BorderStyle, Table, TableRow, TableCell,
    WidthType, ShadingType
} from 'docx';
import { saveAs } from 'file-saver';

function AttackerProfile({ ip, onClose }) {
    const [profile, setProfile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [reportGenerated, setReportGenerated] = useState(false);

    const fetchProfile = async () => {
        const res = await fetch(`http://localhost:8000/api/attacker/${ip}/profile`);
        const data = await res.json();
        setProfile(data);
    };

    const generateReport = async () => {
        setLoading(true);
        const res = await fetch(`http://localhost:8000/api/attacker/${ip}/generate-report`, { method: 'POST' });
        const data = await res.json();
        setProfile(prev => ({
            ...prev,
            ttp_tags: data.ttp_tags,
            profile: data.profile_markdown,
            threat_report: data.threat_report,
        }));
        setReportGenerated(true);
        setLoading(false);
    };

    const downloadWord = async () => {
        const tr = profile.threat_report;
        const now = new Date().toLocaleString();
        const riskColor = {
            CRITICAL: 'FF0000', HIGH: 'FF6600', MEDIUM: 'FFC000', LOW: '00B050', UNKNOWN: '808080'
        }[tr.risk_level] || '808080';

        const makeHeading = (text, level = HeadingLevel.HEADING_2) => new Paragraph({
            text,
            heading: level,
            spacing: { before: 300, after: 100 },
        });

        const makeBullets = (items = []) => items.map(item => new Paragraph({
            children: [new TextRun({ text: `• ${item}`, size: 22 })],
            spacing: { after: 60 },
            indent: { left: 360 },
        }));

        const makeField = (label, value) => new Paragraph({
            children: [
                new TextRun({ text: `${label}: `, bold: true, size: 22 }),
                new TextRun({ text: value || 'N/A', size: 22 }),
            ],
            spacing: { after: 80 },
        });

        const doc = new Document({
            styles: {
                default: {
                    document: {
                        run: { font: 'Calibri', size: 22 },
                    },
                },
            },
            sections: [{
                children: [
                    // ── Title ──────────────────────────────────────────────
                    new Paragraph({
                        children: [
                            new TextRun({
                                text: 'THREAT INTELLIGENCE REPORT',
                                bold: true,
                                size: 40,
                                color: riskColor,
                                allCaps: true,
                            }),
                        ],
                        alignment: AlignmentType.CENTER,
                        spacing: { after: 100 },
                    }),
                    new Paragraph({
                        children: [new TextRun({ text: `Generated: ${now}`, size: 18, color: '808080', italics: true })],
                        alignment: AlignmentType.CENTER,
                        spacing: { after: 400 },
                    }),

                    // ── Target Info ─────────────────────────────────────────
                    makeHeading('Target Information', HeadingLevel.HEADING_1),
                    makeField('IP Address', ip),
                    makeField('Location', `${profile.city || '?'}, ${profile.country || '?'}`),
                    makeField('Risk Score', `${profile.risk_score} / 100`),
                    makeField('Risk Level', tr.risk_level),
                    makeField('Attacker Type', tr.attacker_type),
                    makeField('First Seen', profile.first_seen ? new Date(profile.first_seen).toLocaleString() : 'N/A'),
                    makeField('Last Seen', profile.last_seen ? new Date(profile.last_seen).toLocaleString() : 'N/A'),

                    // ── Executive Summary ───────────────────────────────────
                    makeHeading('Executive Summary', HeadingLevel.HEADING_1),
                    new Paragraph({
                        children: [new TextRun({ text: tr.summary || 'No summary available.', size: 22 })],
                        spacing: { after: 200 },
                    }),

                    // ── Attack Timeline ─────────────────────────────────────
                    ...(tr.timeline?.length > 0 ? [
                        makeHeading('Attack Timeline', HeadingLevel.HEADING_1),
                        ...tr.timeline.map((step, i) => new Paragraph({
                            children: [new TextRun({ text: `${i + 1}. ${step}`, size: 22 })],
                            spacing: { after: 80 },
                            indent: { left: 360 },
                        })),
                    ] : []),

                    // ── MITRE TTPs ──────────────────────────────────────────
                    ...(tr.ttps?.length > 0 ? [
                        makeHeading('MITRE ATT&CK Techniques', HeadingLevel.HEADING_1),
                        ...makeBullets(tr.ttps),
                    ] : []),

                    // ── IOCs ────────────────────────────────────────────────
                    ...(tr.ioc?.length > 0 ? [
                        makeHeading('Indicators of Compromise (IOCs)', HeadingLevel.HEADING_1),
                        ...makeBullets(tr.ioc),
                    ] : []),

                    // ── Recommendations ─────────────────────────────────────
                    ...(tr.recommendations?.length > 0 ? [
                        makeHeading('Recommendations', HeadingLevel.HEADING_1),
                        ...makeBullets(tr.recommendations),
                    ] : []),

                    // ── AI Profile ──────────────────────────────────────────
                    ...(profile.profile && profile.profile !== 'No profile generated yet. Use /generate-report.' ? [
                        makeHeading('AI Attacker Profile', HeadingLevel.HEADING_1),
                        // Strip markdown bold markers for Word
                        ...profile.profile.split('\n').filter(Boolean).map(line => new Paragraph({
                            children: [new TextRun({ text: line.replace(/\*\*/g, ''), size: 22 })],
                            spacing: { after: 60 },
                        })),
                    ] : []),

                    // ── Footer ──────────────────────────────────────────────
                    new Paragraph({
                        children: [new TextRun({ text: '— Generated by CyberSentinel AI Honeypot System —', size: 18, color: '808080', italics: true })],
                        alignment: AlignmentType.CENTER,
                        spacing: { before: 600 },
                    }),
                ],
            }],
        });

        const blob = await Packer.toBlob(doc);
        const filename = `ThreatReport_${ip.replace(/\./g, '_')}_${new Date().toISOString().slice(0, 10)}.docx`;
        saveAs(blob, filename);
    };

    React.useEffect(() => {
        fetchProfile();
    }, [ip]);

    const severityColor = (level) => {
        switch (level) {
            case 'CRITICAL': return 'text-red-400 bg-red-500/10 border-red-500/40';
            case 'HIGH': return 'text-orange-400 bg-orange-500/10 border-orange-500/40';
            case 'MEDIUM': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/40';
            default: return 'text-green-400 bg-green-500/10 border-green-500/40';
        }
    };

    return (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
            <div
                className="relative bg-[#050f05] border border-neon-green/30 rounded-lg w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl shadow-neon-green/10"
                onClick={e => e.stopPropagation()}
            >
                {/* Header */}
                <div className="flex items-center justify-between p-5 border-b border-neon-green/20 sticky top-0 bg-[#050f05] z-10">
                    <div>
                        <h2 className="text-neon-green font-bold text-lg tracking-widest">ATTACKER PROFILE</h2>
                        <p className="text-xs text-gray-400 font-mono">{ip}</p>
                    </div>
                    <button onClick={onClose} className="text-gray-500 hover:text-white text-xl leading-none">✕</button>
                </div>

                <div className="p-5 space-y-5">
                    {!profile ? (
                        <p className="text-gray-500 text-sm text-center py-10">Loading...</p>
                    ) : (
                        <>
                            {/* Stats Row */}
                            <div className="grid grid-cols-3 gap-3">
                                <div className="bg-black/40 border border-neon-green/20 rounded p-3 text-center">
                                    <div className="text-xs text-gray-500 uppercase">Risk Score</div>
                                    <div className={`text-2xl font-bold ${profile.risk_score >= 75 ? 'text-red-400' : profile.risk_score >= 40 ? 'text-yellow-400' : 'text-neon-green'}`}>
                                        {profile.risk_score}
                                    </div>
                                    <div className="text-xs text-gray-600">/ 100</div>
                                </div>
                                <div className="bg-black/40 border border-neon-green/20 rounded p-3 text-center">
                                    <div className="text-xs text-gray-500 uppercase">Location</div>
                                    <div className="text-sm font-bold text-white mt-1">{profile.city || '?'}</div>
                                    <div className="text-xs text-gray-400">{profile.country || '?'}</div>
                                </div>
                                <div className="bg-black/40 border border-neon-green/20 rounded p-3 text-center">
                                    <div className="text-xs text-gray-500 uppercase">Last Seen</div>
                                    <div className="text-xs text-yellow-400 mt-1 font-mono">
                                        {profile.last_seen ? new Date(profile.last_seen).toLocaleString() : 'N/A'}
                                    </div>
                                </div>
                            </div>

                            {/* TTP Tags */}
                            {profile.ttp_tags && (
                                <div>
                                    <div className="text-xs text-neon-green uppercase tracking-wider mb-2">MITRE ATT&CK TTPs</div>
                                    <div className="flex flex-wrap gap-2">
                                        {profile.ttp_tags.split(',').filter(Boolean).map((ttp, i) => (
                                            <span
                                                key={i}
                                                className="px-2 py-1 text-xs font-mono bg-red-500/10 border border-red-500/30 text-red-300 rounded"
                                            >
                                                {ttp.trim()}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* AI Profile */}
                            {profile.profile && profile.profile !== 'No profile generated yet. Use /generate-report.' && (
                                <div>
                                    <div className="text-xs text-neon-green uppercase tracking-wider mb-2">AI Analysis</div>
                                    <div className="bg-black/40 border border-neon-green/10 rounded p-4 text-sm text-gray-300 whitespace-pre-wrap font-mono leading-relaxed">
                                        {profile.profile}
                                    </div>
                                </div>
                            )}

                            {/* Threat Report from Gemini */}
                            {profile.threat_report && (
                                <div>
                                    <div className="text-xs text-neon-green uppercase tracking-wider mb-2">Threat Intelligence Report</div>
                                    <div className="space-y-3">
                                        <div className={`inline-flex px-2 py-1 rounded border text-xs font-bold ${severityColor(profile.threat_report.risk_level)}`}>
                                            RISK: {profile.threat_report.risk_level}
                                        </div>
                                        <p className="text-sm text-gray-300">{profile.threat_report.summary}</p>
                                        {profile.threat_report.timeline?.length > 0 && (
                                            <div>
                                                <div className="text-xs text-gray-500 mb-1 uppercase">Attack Timeline</div>
                                                <ol className="list-decimal list-inside space-y-1">
                                                    {profile.threat_report.timeline.map((step, i) => (
                                                        <li key={i} className="text-xs text-gray-400 font-mono">{step}</li>
                                                    ))}
                                                </ol>
                                            </div>
                                        )}
                                        {profile.threat_report.recommendations?.length > 0 && (
                                            <div>
                                                <div className="text-xs text-gray-500 mb-1 uppercase">Recommendations</div>
                                                <ul className="space-y-1">
                                                    {profile.threat_report.recommendations.map((rec, i) => (
                                                        <li key={i} className="text-xs text-yellow-300 font-mono flex gap-2">
                                                            <span className="text-yellow-500">▸</span>{rec}
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}

                            {/* Action Buttons */}
                            <div className="pt-2 border-t border-neon-green/10 flex gap-3 justify-end flex-wrap">
                                {/* Download Word — only shown after report is generated */}
                                {reportGenerated && profile.threat_report && (
                                    <button
                                        onClick={downloadWord}
                                        className="px-4 py-2 text-xs font-bold bg-blue-500/10 border border-blue-500/40 text-blue-400 rounded hover:bg-blue-500/20 transition-all uppercase tracking-wider flex items-center gap-2"
                                    >
                                        <span>📄</span> Download .docx
                                    </button>
                                )}

                                <button
                                    onClick={generateReport}
                                    disabled={loading}
                                    className="px-4 py-2 text-xs font-bold bg-neon-green/10 border border-neon-green/40 text-neon-green rounded hover:bg-neon-green/20 transition-all uppercase tracking-wider disabled:opacity-50 flex items-center gap-2"
                                >
                                    {loading ? (
                                        <><span className="animate-spin">⟳</span> Generating...</>
                                    ) : (
                                        <><span>🤖</span> {reportGenerated ? 'Regenerate' : 'Generate AI Report'}</>
                                    )}
                                </button>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
}

export default AttackerProfile;
