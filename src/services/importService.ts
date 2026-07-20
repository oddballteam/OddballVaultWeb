/**
 * Import from a plain CSV export of another password manager (Chrome,
 * Bitwarden, LastPass, 1Password, etc. all export a broadly compatible
 * shape). Unlike .ovault import (exportService.ts), there's no encryption
 * envelope to unwrap — the source file is already plaintext, which is
 * inherent to every mainstream password manager's CSV export. Each row is
 * encrypted locally under a fresh Item Key (via vaultService.createItem)
 * before anything reaches Supabase — nothing plaintext ever leaves the
 * browser.
 *
 * Expected header row (case-insensitive, order doesn't matter). Only a
 * title column is required — everything else is optional and left blank
 * if missing:
 *
 *   title | name                     Item title (required)
 *   username | login_username        Login username
 *   password | login_password        Login password
 *   url | login_uri                  Login URL
 *   notes | extra                    Free-form notes
 *
 * The `name`/`login_username`/`login_password`/`login_uri` aliases match
 * Chrome's and Bitwarden's default CSV export column names, so either
 * works without the user needing to rename columns first.
 */
import { emptyEnvelope, type ItemEnvelope } from "../types/vaultItem";
import { createItem, type Owner } from "./vaultService";

interface ImportedRow {
  title?: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
}

const HEADER_ALIASES: Record<string, keyof ImportedRow> = {
  title: "title",
  name: "title",
  username: "username",
  login_username: "username",
  password: "password",
  login_password: "password",
  url: "url",
  login_uri: "url",
  notes: "notes",
  extra: "notes",
};

export interface CsvImportResult {
  imported: number;
  skipped: number;
  errors: string[];
}

/**
 * Minimal RFC4180-style CSV parser — handles quoted fields containing
 * commas, quotes, or newlines. A naive `line.split(',')` would silently
 * corrupt any password or note containing a comma, which is exactly the
 * kind of quiet data-loss bug this import path needs to avoid.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (inQuotes) {
      if (char === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((cell) => cell.trim() !== ""));
}

export async function importCsv(file: File, owner: Owner): Promise<CsvImportResult> {
  const text = await file.text();
  const rows = parseCsv(text);
  if (rows.length === 0) {
    throw new Error("File is empty.");
  }

  const headerRow = rows[0].map((h) => h.trim().toLowerCase());
  const columnMap: Record<number, keyof ImportedRow> = {};
  headerRow.forEach((header, index) => {
    const mapped = HEADER_ALIASES[header];
    if (mapped) columnMap[index] = mapped;
  });

  if (!Object.values(columnMap).includes("title")) {
    throw new Error(
      'CSV must include a "title" or "name" column. Expected headers: title (or name), username, password, url, notes.',
    );
  }

  let imported = 0;
  let skipped = 0;
  const errors: string[] = [];

  for (let i = 1; i < rows.length; i++) {
    const cells = rows[i];
    const rowNumber = i + 1; // 1-based; row 1 is the header
    try {
      const parsed: ImportedRow = {};
      cells.forEach((cell, index) => {
        const key = columnMap[index];
        if (key && cell.trim() !== "") parsed[key] = cell.trim();
      });

      if (!parsed.title) {
        skipped++;
        errors.push(`Row ${rowNumber}: missing title — skipped.`);
        continue;
      }

      const envelope: ItemEnvelope = {
        ...emptyEnvelope(parsed.title),
        username: parsed.username,
        password: parsed.password,
        url: parsed.url,
        notes: parsed.notes,
      };

      await createItem("login", envelope, owner);
      imported++;
    } catch (err) {
      skipped++;
      errors.push(`Row ${rowNumber}: ${err instanceof Error ? err.message : "unknown error"}.`);
    }
  }

  return { imported, skipped, errors };
}
