import type { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) { return <section className={`panel ${className}`}>{children}</section>; }
export function PageTitle({ eyebrow, title, description, action }: { eyebrow: string; title: string; description?: string; action?: ReactNode }) { return <div className="page-title"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1>{description && <p className="page-description">{description}</p>}</div>{action}</div>; }
export function Loading({ label = "Loading evidence…" }: { label?: string }) { return <div className="state-box"><div className="spinner" /><span>{label}</span></div>; }
export function ErrorState({ message, retry }: { message: string; retry?: () => void }) { return <div className="state-box error-state"><p>{message}</p>{retry && <button className="button secondary" onClick={retry}>Retry</button>}</div>; }
export function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="state-box"><p className="empty-title">{title}</p><p>{detail}</p></div>; }
