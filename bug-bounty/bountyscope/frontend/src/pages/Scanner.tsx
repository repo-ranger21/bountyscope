import { useState } from "react";
import { Shield, AlertTriangle, CheckCircle, Zap } from "lucide-react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000/api";

interface ScanResult {
  slug: string;
  verdict: "likely_vulnerable" | "nonce_protected" | "no_handlers_found";
  confidence: "high" | "medium" | "low" | "none";
  file_count: number;
  hit_count: number;
  nonce_hit_count: number;
  has_ajax_handlers: boolean;
  has_admin_post: boolean;
  has_state_changes: boolean;
  has_post_data: boolean;
  has_nonces: boolean;
  top_hits: { file: string; line: number; pattern: string; snippet: string }[];
  duration_ms: number;
}

const VERDICT_CONFIG = {
  likely_vulnerable: { color: "red",   label: "LIKELY VULNERABLE", icon: <AlertTriangle size={20} /> },
  nonce_protected:   { color: "green", label: "NONCE PROTECTED",   icon: <CheckCircle size={20} /> },
  no_handlers_found: { color: "yellow",label: "NO HANDLERS FOUND", icon: <Shield size={20} /> },
};

const CONFIDENCE_COLOR: Record<string, string> = {
  high: "text-red-400", medium: "text-yellow-400", low: "text-blue-400", none: "text-gray-500",
};

export default function Scanner() {
  const [slug, setSlug]       = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<ScanResult | null>(null);
  const [error, setError]     = useState("");
  const [showAll, setShowAll] = useState(false);

  async function runScan() {
    if (!slug.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API}/scanner/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: slug.trim().toLowerCase() }),
      });
      if (!res.ok) {
        const err = await res.json();
        setError(err.detail || "Scan failed.");
        return;
      }
      setResult(await res.json());
    } catch {
      setError("Failed to reach BountyScope API.");
    } finally {
      setLoading(false);
    }
  }

  const signals = result ? [
    { label: "AJAX handlers (wp_ajax_*)",             key: "has_ajax_handlers", vuln: true },
    { label: "Admin POST handlers (admin_post_*)",    key: "has_admin_post",    vuln: true },
    { label: "State changes (update_option, etc)",    key: "has_state_changes", vuln: true },
    { label: "Raw $_POST/$_GET consumption",          key: "has_post_data",     vuln: true },
    { label: "Nonce protection detected",             key: "has_nonces",        vuln: false },
  ] : [];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white mb-1">CSRF Scanner</h2>
        <p className="text-gray-500 text-sm">
          Downloads a plugin from WordPress.org and runs static CSRF/nonce analysis across all PHP files.
        </p>
      </div>

      <div className="flex gap-3">
        <input
          value={slug}
          onChange={(e) => setSlug(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && runScan()}
          placeholder="plugin-slug"
          className="flex-1 bg-gray-900 border border-gray-700 rounded px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-red-500"
        />
        <button
          onClick={runScan}
          disabled={loading || !slug.trim()}
          className="flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:opacity-40 text-white px-5 py-2.5 rounded text-sm font-semibold transition-colors"
        >
          <Zap size={15} />
          {loading ? "Scanning..." : "Run Scan"}
        </button>
      </div>

      {loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 text-center">
          <div className="text-gray-400 text-sm animate-pulse">
            Downloading plugin → Extracting → Running grep suite...
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-950 border border-red-800 rounded p-3 text-red-400 text-sm">{error}</div>
      )}

      {result && (() => {
        const cfg = VERDICT_CONFIG[result.verdict] || VERDICT_CONFIG.no_handlers_found;
        return (
          <div className="space-y-4">
            {/* Verdict banner */}
            <div className={`bg-${cfg.color}-950/40 border border-${cfg.color}-800 rounded-lg p-5`}>
              <div className={`flex items-center gap-3 text-${cfg.color}-400 font-bold text-lg`}>
                {cfg.icon}
                {cfg.label}
              </div>
              <div className="mt-2 flex gap-6 text-sm text-gray-500">
                <span>Confidence: <span className={`font-bold ${CONFIDENCE_COLOR[result.confidence]}`}>{result.confidence.toUpperCase()}</span></span>
                <span>Files: <span className="text-gray-300">{result.file_count}</span></span>
                <span>Hits: <span className="text-gray-300">{result.hit_count}</span></span>
                <span>Nonces: <span className="text-gray-300">{result.nonce_hit_count}</span></span>
                <span>Time: <span className="text-gray-300">{result.duration_ms}ms</span></span>
              </div>
            </div>

            {/* Signal table */}
            <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
              <div className="px-5 py-3 border-b border-gray-800 text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Signal Breakdown
              </div>
              <div className="divide-y divide-gray-800">
                {signals.map(({ label, key, vuln }) => {
                  const found = (result as any)[key] as boolean;
                  const isGood = vuln ? !found : found;
                  return (
                    <div key={key} className="flex items-center justify-between px-5 py-3">
                      <span className="text-sm text-gray-400">{label}</span>
                      <span className={`text-xs font-bold ${found ? (vuln ? "text-red-400" : "text-green-400") : "text-gray-600"}`}>
                        {found ? "FOUND" : "NOT FOUND"}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Top hits */}
            {result.top_hits.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
                <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                    Top Suspicious Code Locations
                  </span>
                  <button
                    onClick={() => setShowAll(!showAll)}
                    className="text-xs text-blue-500 hover:text-blue-400"
                  >
                    {showAll ? "Show less" : `Show all ${result.top_hits.length}`}
                  </button>
                </div>
                <div className="divide-y divide-gray-800 font-mono text-xs">
                  {(showAll ? result.top_hits : result.top_hits.slice(0, 5)).map((hit, i) => (
                    <div key={i} className="px-5 py-3">
                      <div className="flex items-center gap-2 text-cyan-400 mb-1">
                        <span>{hit.file}</span>
                        <span className="text-gray-600">:{hit.line}</span>
                        <span className="bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded text-xs">
                          {hit.pattern}
                        </span>
                      </div>
                      <div className="text-gray-500 pl-2 truncate">{hit.snippet}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.verdict === "likely_vulnerable" && (
              <div className="bg-green-950/30 border border-green-800 rounded p-3 text-green-400 text-sm">
                ✓ Draft finding automatically created in the Target Tracker.
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}
