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
    <div className="app-shell">
      <header className="app-header">
        <h1 className="logo">AlertLens</h1>
        <nav className="main-nav" aria-label="Main navigation">
          <a href="#/" aria-current={route.page === "dashboard" ? "page" : undefined}>Dashboard</a>
          <a href="#/queue" aria-current={route.page === "queue" ? "page" : undefined}>Incident Queue</a>
        </nav>
      </header>
      {route.page === "dashboard" && <Dashboard />}
      {route.page === "queue" && <Queue />}
      {route.page === "detail" && <Detail id={route.id} />}
    </div>
  );
}
