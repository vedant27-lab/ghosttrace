import { Activity, Database, FileSearch, Info, Play, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";

export type Screen = "dashboard" | "case" | "evidence" | "run" | "about";

const nav = [
  { id: "dashboard" as const, label: "Dashboard", icon: Activity },
  { id: "evidence" as const, label: "Evidence explorer", icon: FileSearch },
  { id: "run" as const, label: "Run audit", icon: Play },
  { id: "about" as const, label: "Methodology", icon: Info },
];

export function Shell({ screen, setScreen, children, demo }: { screen: Screen; setScreen: (screen: Screen) => void; children: ReactNode; demo: boolean }) {
  return (
    <div className="min-h-screen bg-canvas text-ink">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark"><ShieldCheck size={19} strokeWidth={2.4} /></div>
          <div><p className="brand-name">GhostTrace</p><p className="brand-subtitle">Privacy operations</p></div>
        </div>
        <div className="mode-pill"><span className={`mode-dot ${demo ? "demo" : "live"}`} />{demo ? "Synthetic demo mode" : "Local dataset mode"}</div>
        <nav className="sidebar-nav" aria-label="Primary navigation">
          {nav.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${screen === id ? "active" : ""}`} onClick={() => setScreen(id)}><Icon size={17} />{label}</button>)}
        </nav>
        <div className="sidebar-footer"><Database size={15} /><span>Evidence-first audit engine</span></div>
      </aside>
      <main className="main-content">
        <header className="topbar"><div className="mobile-brand"><ShieldCheck size={18} /> GhostTrace</div><div className="topbar-meta">Evidence-based assistance <span className="topbar-separator" /> No external AI calls</div></header>
        <div className="page-wrap">{children}</div>
      </main>
    </div>
  );
}
