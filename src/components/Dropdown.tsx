import { ChevronDown } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

export interface DropdownOption<T extends string> {
  value: T;
  label: string;
}

/**
 * One reusable popup-menu component behind every dropdown in the app —
 * both "pick a persistent value" selects (auto-lock, share role) and
 * "trigger an action" menus (+ New item) are the same interaction pattern:
 * a trigger button showing a label, and a rounded popup of options that
 * closes on selection or on an outside click.
 */
export function Dropdown<T extends string>({
  label,
  options,
  onSelect,
  icon,
  disabled,
}: {
  label: string;
  options: DropdownOption<T>[];
  onSelect: (value: T) => void;
  icon?: ReactNode;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleOutsideClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handleOutsideClick);
    return () => document.removeEventListener("mousedown", handleOutsideClick);
  }, []);

  return (
    <div className="dropdown" ref={containerRef}>
      <button
        type="button"
        className="dropdown-trigger"
        disabled={disabled}
        onClick={() => setOpen((o) => !o)}
      >
        {icon}
        {label}
        <ChevronDown size={16} className={open ? "dropdown-chevron open" : "dropdown-chevron"} />
      </button>
      {open && (
        <div className="dropdown-popup">
          {options.map((opt) => (
            <button
              type="button"
              key={opt.value}
              className="dropdown-option"
              onClick={() => {
                onSelect(opt.value);
                setOpen(false);
              }}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
