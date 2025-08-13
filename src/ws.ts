import WebSocket from "ws";

export type WsTrade = { ts: number; price: number; size: number; side: string; fee: number };

export function listenTrades(wsUrl: string, onTrade: (t: WsTrade) => void): () => void {
  console.log("Connecting to WebSocket:", wsUrl);
  const ws = new WebSocket(wsUrl);
  
  ws.on("open", () => {
    console.log("WebSocket connected");
  });
  
  ws.on("error", (err) => {
    console.error("WebSocket error:", err.message);
  });
  
  ws.on("message", (msg: WebSocket.RawData) => {
    try {
      const obj = JSON.parse(msg.toString());
      if (obj?.event === "trade" && obj?.data) {
        console.log("Received trade:", obj.data);
        onTrade(obj.data as WsTrade);
      }
    } catch (e) {
      console.error("Error parsing WS message:", e);
    }
  });
  
  const cleanup = () => {
    try { 
      console.log("Closing WebSocket connection");
      ws.close(); 
    } catch {}
  };
  return cleanup;
}

