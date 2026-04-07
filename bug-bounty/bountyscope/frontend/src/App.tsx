import { useState } from "react";
import ScopeChecker from "./pages/ScopeChecker";
import Scanner from "./pages/Scanner";
import Tracker from "./pages/Tracker";
import { Target, Search, Shield, Activity } from "lucide-react";

type Tab = "scope" | "scanner" | "tracker";

export default function App() {
  const [tab, setTab] = useState<Tab>("scope");

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: "scope",   label: "Scope Checker", icon: <Search size={16} /> },
    { id: "scanner", label: "CSRF Scanner",  icon: <Shield size={16} /> },
    { id: "tracker", label: "Target Tracker",icon: <Target size={16} /> },
  ];

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-mono">
      {/* Top bar */}
      <header className="border-b border-gray-800 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity size={20} className="text-red-500" />
          <span className="text-white font-bold tracking-tight">BountyScope</span>
          <span className="text-gray-600 text-xs">WordPress Bug Bounty Workstation</span>
        </div>
        <span className="text-gray-600 text-xs">@lucius-log</span>
      </header>

      {/* Tab nav */}
      <nav className="border-b border-gray-800 px-6">
        <div className="flex gap-0">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-2 px-5 py-3 text-sm border-b-2 transition-colors ${
                tab === t.id
                  ? "border-red-500 text-white"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              }`}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Page content */}
      <main className="p-6 max-w-5xl mx-auto">
        {tab === "scope"   && <ScopeChecker />}
        {tab === "scanner" && <Scanner />}
        {tab === "tracker" && <Tracker />}
      </main>
    </div>
  );
}
