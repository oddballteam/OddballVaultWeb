import { Plus } from "lucide-react";
import { useEffect, useState } from "react";
import { Dropdown } from "../components/Dropdown";
import { createItem, listItems } from "../services/vaultService";
import { emptyEnvelope, ITEM_TYPE_LABELS, type ItemType, type VaultItem } from "../types/vaultItem";
import { ItemDetailView } from "./ItemDetailView";

const NEW_ITEM_OPTIONS = Object.entries(ITEM_TYPE_LABELS).map(([value, label]) => ({
  value: value as ItemType,
  label,
}));

export function VaultView({ userId, userEmail }: { userId: string; userEmail: string }) {
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [justCreatedId, setJustCreatedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showMobileDetail, setShowMobileDetail] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      setItems(await listItems(userId));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  async function handleCreate(itemType: ItemType) {
    const created = await createItem(itemType, emptyEnvelope(`New ${ITEM_TYPE_LABELS[itemType]}`), {
      type: "user",
      userId,
    });
    await refresh();
    setSelectedId(created.id);
    setJustCreatedId(created.id);
    setShowMobileDetail(true);
  }

  const filtered = items.filter((i) => i.envelope.title.toLowerCase().includes(search.toLowerCase()));
  const selected = items.find((i) => i.id === selectedId) ?? null;

  return (
    <div className="main-panels">
      <div className={`item-list ${showMobileDetail ? "hidden-on-mobile" : ""}`}>
        <input placeholder="Search…" value={search} onChange={(e) => setSearch(e.target.value)} style={{ marginBottom: "0.75rem" }} />
        <Dropdown<ItemType>
          label="New item"
          icon={<Plus size={16} />}
          options={NEW_ITEM_OPTIONS}
          onSelect={(type) => void handleCreate(type)}
        />

        {loading && <p className="muted">Loading…</p>}
        {!loading && filtered.length === 0 && <p className="muted">No items yet.</p>}
        {filtered.map((item) => (
          <div
            key={item.id}
            className={`item-card ${item.id === selectedId ? "selected" : ""}`}
            onClick={() => {
              setSelectedId(item.id);
              setJustCreatedId(null);
              setShowMobileDetail(true);
            }}
          >
            <div className="title">{item.isFavorite ? "★ " : ""}{item.envelope.title}</div>
            <div className="subtitle">{ITEM_TYPE_LABELS[item.itemType]}{item.envelope.username ? ` · ${item.envelope.username}` : ""}</div>
          </div>
        ))}
      </div>

      <div className={`detail-panel ${showMobileDetail ? "" : "hidden-on-mobile"}`} style={{ padding: 0 }}>
        <button className="secondary back-to-list" style={{ margin: "0.5rem" }} onClick={() => setShowMobileDetail(false)}>
          ← Back to list
        </button>
        {selected ? (
          <ItemDetailView
            item={selected}
            userId={userId}
            userEmail={userEmail}
            startInEdit={selected.id === justCreatedId}
            onChanged={refresh}
            onDeleted={() => { setSelectedId(null); void refresh(); }}
          />
        ) : (
          <p className="muted" style={{ padding: "1rem" }}>Select an item, or create a new one.</p>
        )}
      </div>
    </div>
  );
}
