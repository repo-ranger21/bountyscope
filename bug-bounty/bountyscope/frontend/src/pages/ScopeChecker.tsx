import { useState } from "react";
import { Search, AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

interface ScopeResult {
  slug: string;
  plugin: Record<string, any>;
  closed: boolean;
  install_count: number;
  risk_level: string;
  researcher_tier: string;
  any_in_scope: boolean;
  scope_matrix: Record<string, { in_scope: boolean; threshold: number; gap: number }>;
  has_known_cve: boolean;
  existing_cves: any[];
  duplicate_risk: string;
  bounty_estimates: Record<string, { estimate: number }>;
  recommendation: string;
}

export default function ScopeChecker() {
  const [slug, setSlug] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScopeResult | null>(null);
  const [error, setError] = useState("");

  async function check() {
    if (!slug.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API}/scope/${slug.trim().toLowerCase()}`);
      const data = await res.json();
      setResult(data);
    } catch {
      setError("Failed to reach BountyScope API. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  const riskColors: Record<string, string> = {
    critical: "text-red-400", high: "text-orange-400",
    medium: "text-yellow-400", low: "text-blue-400", minimal: "text-gray-500",
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white mb-1">Scope Checker</h2>
        <p className="text-gray-500 text-sm">
          Enter a plugin slug to check install count, existing CVEs, and scope eligibility before investing research time.
        </p>
      </div>

      {/* Input */}
      <div className="flex gap-3">
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && check()}
          placeholder="plugin-slug (e.g. contact-form-7)"
          className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-500"
        />
        <button
          onClick={check}
          disabled={loading || !slug.trim()}
          className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:opacity-40 text-white px-5 py-2.5 rounded text-sm font-semibold transition-colors"
        >
          <Search size={15} />
          {loading ? "Checking..." : "Check Scope"}
        </button>
      </div>

      {error && (
        <div className="bg-red-950 border border-red-800 rounded p-3 text-red-400 text-sm">{error}</div>
      )}

      {result && (
        <div className="space-y-4">
          {/* Plugin header */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-white font-bold text-base">
                    {result.plugin?.name || result.slug}
                  </span>
                  {result.closed && (
                    <span className="bg-red-900/50 text-red-400 text-xs px-2 py-0.5 rounded border border-red-800">
                      CLOSED
                    </span>
                  )}
                </div>
                <div className="text-gray-500 text-xs mt-1 space-x-4">
                  <span>slug: {result.slug}</span>
                  <span>author: {result.plugin?.author || "unknown"}</span>
                  <span>v{result.plugin?.version || "?"}</span>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-2xl font-bold ${riskColors[result.risk_level] || "text-gray-400"}`}>
                  {result.install_count.toLocaleString()}
                </div>
                <div className="text-gray-600 text-xs">active installs</div>
              </div>
            </div>
          </div>

          {/* Scope matrix */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-800 text-xs font-semibold text-gray-400 uppercase tracking-wider">
              Scope Matrix — Tier: {result.researcher_tier}
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-600 text-xs">
                  <th className="text-left px-5 py-2">Vulnerability Class</th>
                  <th className="text-right px-4 py-2">Threshold</th>
                  <th className="text-right px-4 py-2">Your Plugin</th>
                  <th className="text-center px-4 py-2">In Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {Object.entries(result.scope_matrix).map(([cls, data]) => (
                  <tr key={cls} className="hover:bg-gray-800/30">
                    <td className="px-5 py-3 text-gray-300">{cls.replace(/_/g, " ")}</td>
                    <td className="px-4 py-3 text-right text-gray-500">{data.threshold.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right text-gray-400">{result.install_count.toLocaleString()}</td>
                    <td className="px-4 py-3 text-center">
                      {data.in_scope ? (
                        <CheckCircle size={16} className="text-green-500 mx-auto" />
                      ) : (
                        <span className="text-red-500 text-xs">-{data.gap.toLocaleString()}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* CVE warning */}
          {result.has_known_cve && (
            <div className="bg-yellow-950/50 border border-yellow-800 rounded-lg p-4">
              <div className="flex items-center gap-2 text-yellow-400 font-semibold text-sm mb-2">
                <AlertTriangle size={16} />
                {result.existing_cves.length} Known CVE(s) — Duplicate Risk: HIGH
              </div>
              <div className="space-y-1">
                {result.existing_cves.slice(0, 3).map((cve, i) => (
                  <div key={i} className="text-xs text-yellow-600">
                    <span className="text-yellow-500 font-mono">{cve.cve}</span>
                    {" — "}{cve.title.substring(0, 70)}
                    <span className="text-yellow-700"> ({cve.published?.substring(0, 10)})</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Bounty estimates */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
              Bounty Estimates (Directional)
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {Object.entries(result.bounty_estimates).map(([type, est]) => (
                <div key={type} className="bg-gray-800 rounded p-3 text-center">
                  <div className="text-green-400 font-bold text-lg">${est.estimate.toFixed(0)}</div>
                  <div className="text-gray-500 text-xs mt-0.5">{type.replace(/_/g, " ")}</div>
                </div>
              ))}
            </div>
            <p className="text-gray-700 text-xs mt-2">* Estimates only. Actual payout set by Wordfence.</p>
          </div>

          {/* Recommendation */}
          <div className={`rounded-lg p-4 border text-sm font-medium ${
            result.any_in_scope && !result.has_known_cve && !result.closed
              ? "bg-green-950/40 border-green-800 text-green-400"
              : "bg-red-950/40 border-red-800 text-red-400"
          }`}>
            {result.recommendation}
          </div>
        </div>
      )}
    </div>
  );
}
