import { useState, useRef } from 'react';
import './App.css';

function App() {
  const [packets, setPackets] = useState([]);
  const [isLive, setIsLive] = useState(false);
  const ws = useRef(null);

  // Toggle Live Monitoring
  const toggleLive = () => {
    if (isLive) {
      // Stop
      if (ws.current) ws.current.close();
      setIsLive(false);
    } else {
      // Start
      setPackets([]); 
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws.current = new WebSocket(`${protocol}//${window.location.host}/api/live`);
      
      ws.current.onopen = () => console.log("Connected to Live Stream");
      
      ws.current.onmessage = (event) => {
        const packet = JSON.parse(event.data);
        // Prepend new packet (limit to last 500)
        setPackets((prev) => [packet, ...prev].slice(0, 500)); 
      };
      
      setIsLive(true);
    }
  };

  // Handle File Upload
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("pcapfile", file);

    try {
      const response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      setPackets(data);
      setIsLive(false);
      if(ws.current) ws.current.close();
    } catch (error) {
      console.error("Error uploading file:", error);
    }
  };

  return (
    <div className="container" style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1>🕸️ Network Packet Sniffer</h1>
      
      <div className="controls" style={{ marginBottom: "20px", display: "flex", gap: "10px", alignItems: "center" }}>
        <button 
          onClick={toggleLive}
          style={{ 
            padding: "10px 20px", 
            backgroundColor: isLive ? "#e74c3c" : "#2ecc71", 
            color: "white",
            border: "none",
            borderRadius: "5px",
            cursor: "pointer",
            fontWeight: "bold"
          }}
        >
          {isLive ? "Stop Live Capture" : "Start Live Capture"}
        </button>

        <div style={{ marginLeft: "20px" }}>
          <label style={{ marginRight: "10px", fontWeight: "bold" }}>Or Upload PCAP: </label>
          <input type="file" onChange={handleFileUpload} accept=".pcap,.cap" />
        </div>
      </div>

      <div style={{ overflow: "auto", maxHeight: "50vh", border: "1px solid #ddd", borderRadius: "6px" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "800px" }}>
          <thead>
            <tr>
              <th style={{ position: "sticky", top: 0, backgroundColor: "#2c3e50", color: "#ffffff", padding: "12px", borderBottom: "1px solid #ddd", textAlign: "left" }}>Time</th>
              <th style={{ position: "sticky", top: 0, backgroundColor: "#2c3e50", color: "#ffffff", padding: "12px", borderBottom: "1px solid #ddd", textAlign: "left" }}>Source IP</th>
              <th style={{ position: "sticky", top: 0, backgroundColor: "#2c3e50", color: "#ffffff", padding: "12px", borderBottom: "1px solid #ddd", textAlign: "left" }}>Destination IP</th>
              <th style={{ position: "sticky", top: 0, backgroundColor: "#2c3e50", color: "#ffffff", padding: "12px", borderBottom: "1px solid #ddd", textAlign: "left" }}>Protocol</th>
              <th style={{ position: "sticky", top: 0, backgroundColor: "#2c3e50", color: "#ffffff", padding: "12px", borderBottom: "1px solid #ddd", textAlign: "left" }}>Length</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((pkt, index) => (
              <tr key={index} style={{ backgroundColor: index % 2 === 0 ? "#ffffff" : "#f6f8fa", color: "#333" }}>
                <td style={{ padding: "8px", borderBottom: "1px solid #ddd", whiteSpace: "nowrap" }}>{pkt.timestamp}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #ddd", whiteSpace: "nowrap" }}>{pkt.src_ip}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #ddd", whiteSpace: "nowrap" }}>{pkt.dst_ip}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #ddd", whiteSpace: "nowrap" }}>{pkt.protocol}</td>
                <td style={{ padding: "8px", borderBottom: "1px solid #ddd", whiteSpace: "nowrap" }}>{pkt.length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;