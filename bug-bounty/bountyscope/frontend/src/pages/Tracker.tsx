import { useState, useEffect } from "react";
import { Target, RefreshCw, DollarSign, TrendingUp } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

interface TargetRow {
  id: string;
  slug: string;
  name: string;
  install_count: number;
  in_scope: boolean;
  status: string;
  priority: string;
  scope_notes: string;
  updated_at: string;
  wordfence_cves: any[];
}

interface Stats {
  targets: { total: number; in_scope: number; by_status: Record<string, number> };
  findings: { total: number; by_status: Record<string, number> };
  bounties: { total_paid: number; total_estimate: number; submitted: number; accepted: number };
}

const STATUS_COLORS: Record<string, string> = {
  queued:    "bg-gray-700 text-gray-300",
  scanning:  "bg-blue-900 text-blue-300",
  reviewed:  "bg-yellow-900 text-yellow-300",
  reported:  "bg-cyan-900 text-cyan-300",
  paid:      "bg-green-900 text-green-300",
  dismissed: "bg-red-900/50 text-red-400",
};

const PRIORITY_COLORS: Record<string, string> = {
  high:   "text-red-400",
  medium: "text-yellow-400",
  low:    "text-gray-500",
};

const STATUSES = ["queued", "scanning", "reviewed", "reported", "paid", "dismissed"];

export default function Tracker() {
  const [targets, setTargets] = useState<TargetRow[]>([]);
  const [stats, setStats]     = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter]   = useState("");

  useEffect(() => { fetchAll(); }, []);

  async function fetchAll() {
    setLoading(true);
    try {
      const [tRes, sRes] = await Promise.all([
        fetch(`${API}/targets/`),
        fetch(`${API}/targets/stats/summary`),
      ]);
      setTargets(await tRes.json());
      setStats(await sRes.json());
    } catch {
      // swallow — show empty state
    } finally {
      setLoading(false);
    }
  }

  async function updateStatus(slug: string, status: string) {
    await fetch(`${API}/targets/${slug}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    fetchAll();
  }

  const filtered = targets.filter(
    (t) =>
      !filter ||
      t.slug.includes(filter.toLowerCase()) ||
      (t.name || "").toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white mb-1">Target Tracker</h2>
        <p className="text-gray-500 text-sm">
          Full pipeline view. Targets are auto-added when you run a scope check or scan.
        </p>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Total Targets",   value: stats.targets.total,                      icon: <Target size={14} /> },
            { label: "In Scope",        value: stats.targets.in_scope,                   icon: <TrendingUp size={14} /> },
            { label: "Paid Out",        value: `$${stats.bounties.total_paid.toFixed(0)}`,icon: <DollarSign size={14} /> },
            { label: "Est. Pipeline",   value: `$${stats.bounties.total_estimate.toFixed(0)}`, icon: <DollarSign size={14} /> },
          ].map(({ label, value, icon }) => (
            <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <div className="flex items-center gap-1.5 text-gray-500 text-xs mb-1">
                {icon} {label}
              </div>
              <div className="text-white font-bold text-xl">{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter + refresh */}
      <div className="flex gap-3">
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by slug or name..."
          className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-500"
        />
        <button
          onClick={fetchAll}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded text-sm transition-colors"
        >
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* Target table */}
      {loading ? (
        <div className="text-gray-600 text-sm animate-pulse py-8 text-center">Loading targets...</div>
      ) : filtered.length === 0 ? (
        <div className="text-gray-600 text-sm py-8 text-center">
          No targets yet. Run a scope check or scan to add targets automatically.
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-gray-600 text-xs">
                <th className="text-left px-5 py-3">Plugin</th>
                <th className="text-right px-4 py-3">Installs</th>
                <th className="text-center px-4 py-3">Scope</th>
                <th className="text-center px-4 py-3">CVEs</th>
                <th className="text-center px-4 py-3">Priority</th>
                <th className="text-center px-4 py-3">Status</th>
                <th className="text-right px-4 py-3">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filtered.map((t) => (
                <tr key={t.id} className="hover:bg-gray-800/30 transition-colors">
                  <td className="px-5 py-3">
                    <div className="text-cyan-400 font-mono text-xs">{t.slug}</div>
                    {t.name && t.name !== t.slug && (
                      <div className="text-gray-500 text-xs truncate max-w-[200px]">{t.name}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right text-gray-400 tabular-nums">
                    {(t.install_count || 0).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={t.in_scope ? "text-green-500" : "text-red-500"}>
                      {t.in_scope ? "✓" : "✗"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    {(t.wordfence_cves || []).length > 0 ? (
                      <span className="text-yellow-500 text-xs font-bold">
                        {t.wordfence_cves.length}
                      </span>
                    ) : (
                      <span className="text-gray-700">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={`text-xs font-bold ${PRIORITY_COLORS[t.priority] || "text-gray-500"}`}>
                      {t.priority || "medium"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <select
                      value={t.status}
                      onChange={(e) => updateStatus(t.slug, e.target.value)}
                      className={`text-xs px-2 py-1 rounded border-0 cursor-pointer ${STATUS_COLORS[t.status] || "bg-gray-700 text-gray-300"}`}
                    >
                      {STATUSES.map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3 text-right text-gray-600 text-xs">
                    {(t.updated_at || "").substring(0, 10)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
