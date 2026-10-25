import { useEffect, useMemo, useState } from "react";
import { ArrowRight, CheckCircle2, CircleAlert, Filter, Search, ShieldAlert } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { api } from "../lib/api";
import type { CasePage, DeletionStatus, Summary } from "../types";
import { Card, EmptyState, ErrorState, Loading, PageTitle } from "../components/Primitives";
import { StatusBadge } from "../components/StatusBadge";

const chartColors = ["#0f766e", "#d97706", "#94a3b8"];

export function Dashboard({ onOpenCase }: { onOpenCase: (caseId: string) => void }) {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [cases, setCases] = useState<CasePage | null>(null);
  const [status, setStatus] = useState<"ALL" | DeletionStatus>("ALL");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [error, setError] = useState("");

  const load = () => {
    setError("");
    Promise.all([
      api.summary(),
      api.cases(new URLSearchParams({ page: String(page), page_size: "10", ...(status !== "ALL" ? { status } : {}), ...(query ? { q: query } : {}) })),
    ]).then(([nextSummary, nextCases]) => { setSummary(nextSummary); setCases(nextCases); }).catch((reason: Error) => setError(reason.message));
  };
  useEffect(load, [page, status]);
  useEffect(() => { const timer = window.setTimeout(() => { setPage(1); load(); }, 280); return () => window.clearTimeout(timer); }, [query]);

  const chartData = useMemo(() => summary ? [
    { name: "Complete", value: summary.status_counts.complete },
    { name: "Incomplete", value: summary.status_counts.incomplete },
    { name: "Not applicable", value: summary.status_counts.not_applicable },
  ] : [], [summary]);

  return <>
    <PageTitle eyebrow="Overview" title="Deletion audit command center" description="Trace every request from identity resolution to evidence-backed remediation." action={<button className="button primary" onClick={() => window.location.hash = "run"}><ShieldAlert size={16} /> Run audit</button>} />
    {error && <ErrorState message={error} retry={load} />}
    {!summary || !cases ? <Loading label="Loading audit index…" /> : <>
      {summary.demo && <div className="demo-banner"><span className="mode-dot demo" /><strong>Demo mode</strong><span>The participant dataset is not connected. These cases are synthetic fixtures for the interface only.</span></div>}
      <div className="metric-grid">
        <Metric label="Total requests" value={summary.total_requests} icon={<ShieldAlert size={17} />} tone="navy" />
        <Metric label="Complete" value={summary.status_counts.complete} icon={<CheckCircle2 size={17} />} tone="green" />
        <Metric label="Incomplete" value={summary.status_counts.incomplete} icon={<CircleAlert size={17} />} tone="amber" />
        <Metric label="Not applicable" value={summary.status_counts.not_applicable} icon={<Filter size={17} />} tone="slate" />
      </div>
      <div className="dashboard-grid">
        <Card><div className="panel-heading"><div><p className="eyebrow">Distribution</p><h2>Case status</h2></div><span className="muted-label">{summary.total_requests} requests</span></div><div className="chart-wrap"><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={chartData} dataKey="value" nameKey="name" innerRadius={63} outerRadius={87} paddingAngle={3}>{chartData.map((entry, index) => <Cell key={entry.name} fill={chartColors[index]} />)}</Pie><Tooltip formatter={(value) => [value, "Cases"]} /></PieChart></ResponsiveContainer><div className="chart-legend">{chartData.map((item, index) => <div key={item.name} className="legend-row"><span className="legend-dot" style={{ background: chartColors[index] }} />{item.name}<strong>{item.value}</strong></div>)}</div></div></Card>
        <Card><div className="panel-heading"><div><p className="eyebrow">Operating principle</p><h2>Evidence before certainty</h2></div></div><div className="principle-copy"><p>Workflow status is a claim. GhostTrace checks identity history, time cutoffs, residual resources, policy treatment, and recreation paths before classifying a request.</p><div className="principle-callout"><span className="callout-line" /><span>Missing evidence is surfaced as uncertainty — never silently treated as deletion proof.</span></div></div></Card>
      </div>
      <Card className="cases-panel"><div className="panel-heading"><div><p className="eyebrow">Case index</p><h2>Audit cases</h2></div><span className="muted-label">{cases.total} matching</span></div><div className="filters"><label className="search-input"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search case ID or masked email" /></label><select value={status} onChange={(event) => { setStatus(event.target.value as typeof status); setPage(1); }} aria-label="Filter by deletion status"><option value="ALL">All statuses</option><option value="COMPLETE">Complete</option><option value="INCOMPLETE">Incomplete</option><option value="NOT_APPLICABLE">Not applicable</option></select></div>{cases.items.length === 0 ? <EmptyState title="No cases match" detail="Try changing the status or search filter." /> : <div className="table-scroll"><table><thead><tr><th>Case</th><th>Status</th><th>Requested</th><th>Audit cutoff</th><th>Request</th><th /></tr></thead><tbody>{cases.items.map(item => <tr key={item.case_id} onClick={() => onOpenCase(item.case_id)}><td className="mono strong">{item.case_id}</td><td><StatusBadge status={item.deletion_status} /></td><td>{formatDate(item.requested_at)}</td><td>{formatDate(item.audit_at)}</td><td className="request-cell">{item.request_excerpt}</td><td><ArrowRight size={16} className="row-arrow" /></td></tr>)}</tbody></table></div>}<div className="pagination"><button className="button ghost" disabled={page === 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page} of {Math.max(1, Math.ceil(cases.total / cases.page_size))}</span><button className="button ghost" disabled={page * cases.page_size >= cases.total} onClick={() => setPage(page + 1)}>Next</button></div></Card>
    </>}
  </>;
}

function Metric({ label, value, icon, tone }: { label: string; value: number; icon: React.ReactNode; tone: string }) { return <Card className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><p>{label}</p><strong>{value.toLocaleString()}</strong><span className="metric-foot">Live from backend</span></Card>; }
function formatDate(value: string) { if (!value) return "—"; return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", year: "numeric" }).format(new Date(value)); }
