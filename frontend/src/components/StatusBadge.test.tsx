import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusBadge } from "./StatusBadge";

describe("StatusBadge", () => {
  it("renders the backend status as an accessible label", () => {
    render(<StatusBadge status="INCOMPLETE" />);
    expect(screen.getByText("Incomplete")).toBeInTheDocument();
    expect(screen.getByText("Incomplete")).toHaveClass("status-incomplete");
  });
});
