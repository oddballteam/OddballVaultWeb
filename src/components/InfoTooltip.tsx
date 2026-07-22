import { Info } from "lucide-react";
import { useState, type ReactNode } from "react";

/** Hover-triggered explanatory blurb next to a heading, instead of a permanently-visible paragraph. */
export function InfoTooltip({ text }: { text: ReactNode }) {
  const [open, setOpen] = useState(false);

  return (
    <span
      className="info-tooltip"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      tabIndex={0}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <Info size={15} />
      {open && <span className="info-tooltip-popup">{text}</span>}
    </span>
  );
}
