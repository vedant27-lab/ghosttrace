import { useEffect, useState } from "react";
import { Shell, type Screen } from "./components/Shell";
import { Dashboard } from "./pages/Dashboard";
import { CaseExplorer } from "./pages/CaseExplorer";
import { EvidenceExplorer } from "./pages/EvidenceExplorer";
import { RunAudit } from "./pages/RunAudit";
import { About } from "./pages/About";
import { api } from "./lib/api";

function screenFromHash(): Screen { const hash = window.location.hash.replace("#", ""); return ["dashboard", "case", "evidence", "run", "about"].includes(hash) ? hash as Screen : "dashboard"; }

export default function App() {
  const [screen, setScreenState] = useState<Screen>(screenFromHash());
  const [caseId, setCaseId] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const [demo, setDemo] = useState(false);
  useEffect(() => { api.summary().then(summary => setDemo(summary.demo)).catch(() => undefined); const listener = () => setScreenState(screenFromHash()); window.addEventListener("hashchange", listener); return () => window.removeEventListener("hashchange", listener); }, []);
  const setScreen = (next: Screen) => { window.location.hash = next; setScreenState(next); };
  return <Shell screen={screen} setScreen={setScreen} demo={demo}>{screen === "dashboard" && <Dashboard onOpenCase={(id) => { setCaseId(id); setScreen("case"); }} />}{screen === "case" && <CaseExplorer caseId={caseId} onBack={() => setScreen("dashboard")} onEvidence={(id) => { setEvidenceId(id); setScreen("evidence"); }} />}{screen === "evidence" && <EvidenceExplorer selectedId={evidenceId} />}{screen === "run" && <RunAudit />}{screen === "about" && <About />}</Shell>;
}
