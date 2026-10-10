import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet";

// Geolocated points with usable coordinates.
function mappable(locations) {
  return (locations || []).filter(
    (l) => typeof l.lat === "number" && typeof l.lon === "number",
  );
}

// Teal circle marker (matching the theme) instead of the default Leaflet icon:
// no asset to load, and it fits the "recon" look.
const MARKER = {
  color: "#35d3b7",
  weight: 2,
  fillColor: "#35d3b7",
  fillOpacity: 0.35,
};

export default function InfraMap({ locations }) {
  const points = mappable(locations);

  if (points.length === 0) {
    return <div className="map-empty">No geolocated IP to display.</div>;
  }

  const avgLat = points.reduce((s, p) => s + p.lat, 0) / points.length;
  const avgLon = points.reduce((s, p) => s + p.lon, 0) / points.length;

  return (
    <div className="map-card">
      <MapContainer
        center={[avgLat, avgLon]}
        zoom={points.length === 1 ? 5 : 3}
        scrollWheelZoom={false}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {points.map((p, i) => (
          <CircleMarker key={`${p.ip}-${i}`} center={[p.lat, p.lon]} radius={9} pathOptions={MARKER}>
            <Popup>
              <strong>{p.ip}</strong>
              <br />
              {(p.city || "?") + ", " + (p.country || "?")}
              <br />
              {p.org || p.isp || ""}
              <br />
              <span style={{ color: "#666" }}>{p.as || ""}</span>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
