import { useEffect, useState } from "react";
import Dashboard from "./pages/Dashboard.jsx";
import Queue from "./pages/Queue.jsx";
import Detail from "./pages/Detail.jsx";

/** Tiny hash router: #/ , #/queue , #/incident/<id>. No router dependency. */
export function parseHash(hash) {
  if (hash.startsWith("#/incident/")) return { page: "detail", id: hash.split("/")[2] };
  if (hash === "#/queue") return { page: "queue" };
  return { page: "dashboard" };
}

export default function App() {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  useEffect(() => {
    const onHash = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 960, margin: "0 auto", padding: 16 }}>
      <header>
        <h1>AlertLens</h1>
        <nav style={{ display: "flex", gap: 16 }}>
          <a href="#/">Dashboard</a>
          <a href="#/queue">Incident Queue</a>
        </nav>
      </header>
      {route.page === "dashboard" && <Dashboard />}
      {route.page === "queue" && <Queue />}
      {route.page === "detail" && <Detail id={route.id} />}
    </div>
  );
}
