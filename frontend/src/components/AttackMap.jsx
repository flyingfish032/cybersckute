import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix for default marker icon in Leaflet with Vite/Webpack
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

let DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});

L.Marker.prototype.options.icon = DefaultIcon;

const AttackMap = ({ attackers }) => {
    return (
        <div className="h-96 w-full rounded border border-neon-green/30 overflow-hidden glow-box map-container">
            <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom={false} style={{ height: "100%", width: "100%" }}>
                {/* Dark Matter / Dark tiles */}
                <TileLayer
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
                    url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                />
                {attackers.map((attacker) => (
                    attacker.latitude && attacker.longitude && (
                        <Marker key={attacker.id} position={[attacker.latitude, attacker.longitude]}>
                            <Popup>
                                <div className="text-black font-bold">
                                    IP: {attacker.ip_address}<br />
                                    Country: {attacker.country}<br />
                                    Risk: {attacker.risk_score}
                                </div>
                            </Popup>
                        </Marker>
                    )
                ))}
            </MapContainer>
        </div>
    );
};

export default AttackMap;
