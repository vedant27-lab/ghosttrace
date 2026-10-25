import type { DeletionStatus } from "../types";

const labels: Record<DeletionStatus, string> = {
  COMPLETE: "Complete",
  INCOMPLETE: "Incomplete",
  NOT_APPLICABLE: "Not applicable",
};

export function StatusBadge({ status }: { status: DeletionStatus }) {
  return <span className={`status-badge status-${status.toLowerCase()}`}>{labels[status]}</span>;
}
