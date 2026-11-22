import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search, AlertTriangle, CheckCircle, XCircle, Loader2, Globe, Shield,
  Clock, Info, Lock, Unlock, Zap, Database, Eye, AlertCircle, ChevronDown, ChevronUp,
} from 'lucide-react';
import { useLang } from '../context/LanguageContext';
import { scanLink } from '../api';
import { recordUserActivity } from '../lib/userStats';

// ─── Types ───────────────────────────────────────────────────────────────────

type OverallStatus = 'Trusted' | 'Low Risk' | 'Moderate Risk' | 'Suspicious' | 'Dangerous' | 'Blocked' | 'Unknown';

interface TechnicalCheck {
  check: string;
  passed: boolean;
  detail: string;
}

interface ScoreFactor {
  factor: string;
  impact: number;
}

interface ApiSourceStatus {
  configured: boolean;
  used: boolean;
  label: string;
}

interface ApiStatus {
  virustotal: ApiSourceStatus;
  google_safe_browsing: ApiSourceStatus;
  heuristics: ApiSourceStatus;
}

interface ScanResult {
  // Core structured fields (new)
  normalizedUrl: string;
  originalInput: string;
  hostname: string;
  overallStatus: OverallStatus;
  riskScore: number;
  confidencePercent: number;
  confidenceLabel: string;
  technicalChecks: TechnicalCheck[];
  scoreFactors: ScoreFactor[];
  threatIndicators: string[];
  apiStatus: ApiStatus;
  recommendations: string[];
  // Domain info
  domainAge: string;
  connectionStatus: string;
  invalidDomain: boolean;
  // VirusTotal stats (legacy, still shown)
  maliciousCount: number;
  suspiciousCount: number;
  safeCount: number;
  undetectedCount: number;
  totalEngines: number;
}

// ─── Status config ────────────────────────────────────────────────────────────

const statusConfig: Record<OverallStatus, {
  icon: React.ElementType;
  color: string;
  textColor: string;
  border: string;
  bg: string;
  badge: string;
  labelHi: string;
}> = {
  Trusted: {
    icon: CheckCircle,
    color: 'text-emerald-400',
    textColor: 'text-emerald-400',
    border: 'border-emerald-500/30',
    bg: 'bg-emerald-500/5',
    badge: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40',
    labelHi: 'विश्वसनीय',
  },
  'Low Risk': {
    icon: CheckCircle,
    color: 'text-green-400',
    textColor: 'text-green-400',
    border: 'border-green-500/30',
    bg: 'bg-green-500/5',
    badge: 'bg-green-500/20 text-green-300 border border-green-500/40',
    labelHi: 'कम जोखिम',
  },
  'Moderate Risk': {
    icon: AlertCircle,
    color: 'text-yellow-400',
    textColor: 'text-yellow-400',
    border: 'border-yellow-500/30',
    bg: 'bg-yellow-500/5',
    badge: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40',
    labelHi: 'मध्यम जोखिम',
  },
  Suspicious: {
    icon: AlertTriangle,
    color: 'text-orange-400',
    textColor: 'text-orange-400',
    border: 'border-orange-500/30',
    bg: 'bg-orange-500/5',
    badge: 'bg-orange-500/20 text-orange-300 border border-orange-500/40',
    labelHi: 'संदिग्ध',
  },
  Dangerous: {
    icon: XCircle,
    color: 'text-red-400',
    textColor: 'text-red-400',
    border: 'border-red-500/30',
    bg: 'bg-red-500/5',
    badge: 'bg-red-500/20 text-red-300 border border-red-500/40',
    labelHi: 'खतरनाक',
  },
  Blocked: {
    icon: Shield,
    color: 'text-rose-400',
    textColor: 'text-rose-400',
    border: 'border-rose-500/30',
    bg: 'bg-rose-500/5',
    badge: 'bg-rose-500/20 text-rose-300 border border-rose-500/40',
    labelHi: 'प्रतिबंधित',
  },
  Unknown: {
    icon: Info,
    color: 'text-slate-400',
    textColor: 'text-slate-400',
    border: 'border-slate-500/30',
    bg: 'bg-slate-500/5',
    badge: 'bg-slate-500/20 text-slate-300 border border-slate-500/40',
    labelHi: 'अज्ञात',
  },
};

// ─── Risk gauge ───────────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const clampedScore = Math.min(100, Math.max(0, score));
  const color =
    clampedScore <= 10 ? '#34d399'
    : clampedScore <= 25 ? '#4ade80'
    : clampedScore <= 45 ? '#facc15'
    : clampedScore <= 70 ? '#fb923c'
    : '#f87171';

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative w-20 h-20">
        <svg className="w-20 h-20 -rotate-90" viewBox="0 0 64 64">
          <circle cx="32" cy="32" r="26" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
          <circle
            cx="32" cy="32" r="26"
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={`${(clampedScore / 100) * 163.4} 163.4`}
            style={{ transition: 'stroke-dasharray 0.8s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-white font-bold text-lg font-mono">{clampedScore}</span>
        </div>
      </div>
      <p className="text-slate-500 text-xs">Risk Score</p>
    </div>
  );
}

// ─── Confidence bar ───────────────────────────────────────────────────────────

function ConfidenceBar({ percent, label }: { percent: number; label: string }) {
  return (
    <div className="flex-1 min-w-0">
      <div className="flex items-center justify-between mb-1">
        <span className="text-slate-400 text-xs">Confidence</span>
        <span className="text-white text-xs font-mono font-bold">{percent}%</span>
      </div>
      <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${percent}%` }}
          transition={{ duration: 0.7, ease: 'easeOut' }}
          className="h-full rounded-full bg-gradient-to-r from-blue-500 to-cyan-400"
        />
      </div>
      <p className="text-slate-600 text-xs mt-1.5 leading-snug">{label}</p>
    </div>
  );
}

// ─── Card wrapper ─────────────────────────────────────────────────────────────

function Card({ title, icon: Icon, children, className = '' }: {
  title: string; icon: React.ElementType; children: React.ReactNode; className?: string;
}) {
  return (
    <div className={`bg-white/5 backdrop-blur border border-slate-700/50 rounded-2xl p-5 ${className}`}>
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-cyan-400 flex-shrink-0" />
        <p className="text-cyan-400 text-xs font-semibold uppercase tracking-wider">{title}</p>
      </div>
      {children}
    </div>
  );
}

// ─── Section toggle ───────────────────────────────────────────────────────────

function CollapsibleCard({ title, icon, children, defaultOpen = false }: {
  title: string; icon: React.ElementType; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const Icon = icon;
  return (
    <div className="bg-white/5 backdrop-blur border border-slate-700/50 rounded-2xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-white/5 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="w-4 h-4 text-cyan-400" />
          <span className="text-cyan-400 text-xs font-semibold uppercase tracking-wider">{title}</span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden px-5 pb-5"
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function LinkScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');
  const { t } = useLang();

  /** UX-only normalization: prepend https:// if bare domain entered */
  function uxNormalize(raw: string): string {
    const trimmed = raw.trim();
    if (!trimmed) return trimmed;
    const lower = trimmed.toLowerCase();
    if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
      return 'https://' + trimmed;
    }
    return trimmed;
  }

  const displayUrl = url.trim() ? uxNormalize(url) : '';
  const showNormHint = url.trim() !== '' && displayUrl !== url.trim();

  async function scan() {
    const raw = url.trim();
    if (!raw) return;

    // Client-side: just need something parseable to send — backend will normalize
    const toSend = uxNormalize(raw);

    setLoading(true);
    setResult(null);
    setError('');

    try {
      const data = await scanLink(toSend);

      // Map legacy verdict to OverallStatus when new field absent
      const overallStatus: OverallStatus = (() => {
        if (data.overall_status) return data.overall_status as OverallStatus;
        const v = data.verdict?.toLowerCase();
        if (v === 'safe' || v === 'malware-free') return 'Low Risk';
        if (v === 'suspicious' || v === 'moderate') return 'Suspicious';
        if (v === 'dangerous' || v === 'malicious') return 'Dangerous';
        return 'Unknown';
      })();

      const vtStats = data.virusTotal?.stats || {};
      const maliciousCount = Number(data.malicious_count ?? vtStats.malicious ?? 0);
      const suspiciousCount = Number(data.suspicious_count ?? vtStats.suspicious ?? 0);
      const safeCount = Number(data.safe_count ?? vtStats.harmless ?? 0);
      const undetectedCount = Number(data.undetected_count ?? vtStats.undetected ?? 0);
      const totalEngines = Number(data.total_engines ?? 0);

      const apiStatus: ApiStatus = data.api_status ?? {
        heuristics: { configured: true, used: true, label: 'Local Heuristics' },
        virustotal: {
          configured: Boolean(data.virusTotal?.configured),
          used: totalEngines > 0,
          label: 'VirusTotal',
        },
        google_safe_browsing: {
          configured: Boolean(data.googleSafeBrowsing?.configured),
          used: Boolean(data.googleSafeBrowsing?.configured),
          label: 'Google Safe Browsing',
        },
      };

      const technicalChecks: TechnicalCheck[] = Array.isArray(data.technical_checks)
        ? data.technical_checks
        : [];

      const scoreFactors: ScoreFactor[] = Array.isArray(data.score_factors)
        ? data.score_factors
        : [];

      const threatIndicators: string[] = Array.isArray(data.threat_indicators)
        ? data.threat_indicators
        : (Array.isArray(data.threats) ? data.threats : []);

      const recommendations: string[] = Array.isArray(data.recommendations) && data.recommendations.length > 0
        ? data.recommendations
        : ['No specific recommendations. Proceed with normal caution.'];

      const confidencePercent = Number(data.confidence_percent ?? Math.round((data.confidence ?? 0.4) * 100));
      const confidenceLabel = data.confidence_label ?? (
        confidencePercent <= 55
          ? 'Confidence based on local analysis only'
          : 'Confidence reflects heuristics and reputation API results'
      );

      recordUserActivity(
        'link',
        ['Dangerous', 'Suspicious'].includes(overallStatus) ? 'suspicious' : 'safe',
        threatIndicators[0] || `Scan complete — ${overallStatus}`
      );

      setResult({
        normalizedUrl: data.normalized_url ?? toSend,
        originalInput: data.original_input ?? raw,
        hostname: data.hostname ?? (new URL(toSend).hostname),
        overallStatus,
        riskScore: Number(data.risk_score ?? 0),
        confidencePercent,
        confidenceLabel,
        technicalChecks,
        scoreFactors,
        threatIndicators,
        apiStatus,
        recommendations,
        domainAge: data.domainInfo?.age || 'Unknown',
        connectionStatus: data.connection_status || (data.invalid_domain ? 'Unreachable' : 'Reachable'),
        invalidDomain: Boolean(data.invalid_domain),
        maliciousCount,
        suspiciousCount,
        safeCount,
        undetectedCount,
        totalEngines,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : t('Failed to scan link.', 'लिंक स्कैन नहीं हो सका।'));
    } finally {
      setLoading(false);
    }
  }

  const sc = result ? statusConfig[result.overallStatus] ?? statusConfig['Unknown'] : null;

  return (
    <div className="min-h-screen bg-[#060d1f] pt-16">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-12">

        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
            <Search className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h1 className="font-['Space_Grotesk'] text-3xl font-bold text-white">
              {t('Link Scanner', 'लिंक स्कैनर')}
            </h1>
            <p className="text-slate-500 text-sm">{t('Check any URL before you click', 'क्लिक करने से पहले URL जांचें')}</p>
          </div>
        </div>

        {/* Warning banner */}
        <div className="bg-white/5 backdrop-blur-xl border border-orange-500/20 rounded-xl p-4 mb-8 flex gap-3">
          <Info className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
          <p className="text-slate-400 text-sm">
            {t(
              'Never click suspicious links from unknown senders. Always scan first.',
              'अनजान लोगों के संदिग्ध लिंक पर कभी क्लिक न करें। पहले स्कैन करें।'
            )}
          </p>
        </div>

        {/* Input card */}
        <motion.div
          whileHover={{ rotateX: -2, rotateY: 2 }}
          style={{ transformStyle: 'preserve-3d' }}
          className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 mb-4"
        >
          <label className="text-slate-400 text-sm font-medium block mb-2">
            {t('Paste the URL to scan', 'स्कैन करने के लिए URL डालें')}
          </label>
          <div className="flex-1 relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
            <input
              type="text"
              value={url}
              onChange={e => { setUrl(e.target.value); setResult(null); setError(''); }}
              onKeyDown={e => e.key === 'Enter' && scan()}
              placeholder="google.com or https://example.com"
              className="w-full bg-[#060d1f] border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-white text-sm placeholder-slate-600 focus:outline-none focus:border-blue-500/50 transition-colors"
            />
          </div>
          {/* UX normalization hint */}
          {showNormHint && (
            <p className="text-slate-600 text-xs mt-2 font-mono">
              ↳ {t('Will scan as:', 'स्कैन होगा:')} <span className="text-slate-400">{displayUrl}</span>
            </p>
          )}
        </motion.div>

        {/* Scan button */}
        <button
          onClick={scan}
          disabled={loading || !url.trim()}
          className="w-full flex items-center justify-center gap-3 py-4 bg-blue-500 hover:bg-blue-400 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-bold text-base rounded-xl transition-all mb-2"
        >
          {loading
            ? <><Loader2 className="w-5 h-5 animate-spin" />{t('Scanning…', 'स्कैन हो रहा है…')}</>
            : <><Shield className="w-5 h-5" />{t('Scan This Link', 'इस लिंक को स्कैन करें')}</>
          }
        </button>

        {error && <p className="mt-3 text-sm text-red-300">{error}</p>}

        {/* ── Results ─────────────────────────────────────────────────────── */}
        <AnimatePresence>
          {result && sc && (
            <motion.div
              key="results"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 8 }}
              transition={{ duration: 0.3 }}
              className="mt-8 space-y-4"
            >

              {/* ── Card 1: Overall Verdict ───────────────────────────────── */}
              <div className={`border rounded-2xl p-5 backdrop-blur-xl ${sc.border} ${sc.bg}`}>
                <div className="flex items-start gap-4">
                  {/* Icon + status */}
                  <div className="flex flex-col items-center gap-2 flex-shrink-0">
                    <sc.icon className={`w-10 h-10 ${sc.color}`} />
                    <span className={`px-2.5 py-1 rounded-full text-xs font-bold ${sc.badge}`}>
                      {t(result.overallStatus, result.overallStatus === 'Trusted' ? 'विश्वसनीय'
                        : result.overallStatus === 'Low Risk' ? 'कम जोखिम'
                        : result.overallStatus === 'Moderate Risk' ? 'मध्यम जोखिम'
                        : result.overallStatus === 'Suspicious' ? 'संदिग्ध'
                        : result.overallStatus === 'Dangerous' ? 'खतरनाक'
                        : 'अज्ञात')}
                    </span>
                  </div>

                  {/* Risk gauge */}
                  <RiskGauge score={result.riskScore} />

                  {/* Confidence bar + URL info */}
                  <div className="flex-1 min-w-0 space-y-3">
                    <ConfidenceBar percent={result.confidencePercent} label={result.confidenceLabel} />

                    {/* Original → Normalized */}
                    <div className="space-y-1">
                      <div className="flex items-start gap-2">
                        <span className="text-slate-600 text-xs w-16 flex-shrink-0 pt-0.5">Input</span>
                        <span className="text-slate-400 text-xs font-mono truncate">{result.originalInput}</span>
                      </div>
                      <div className="flex items-start gap-2">
                        <span className="text-slate-600 text-xs w-16 flex-shrink-0 pt-0.5">Scanned</span>
                        <span className="text-cyan-400 text-xs font-mono truncate">{result.normalizedUrl}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* ── Card 2: Security Sources ──────────────────────────────── */}
              <Card title={t('Security Sources', 'सुरक्षा स्रोत')} icon={Database}>
                <div className="space-y-2">
                  {[
                    result.apiStatus.heuristics,
                    result.apiStatus.virustotal,
                    result.apiStatus.google_safe_browsing,
                  ].map(src => (
                    <div key={src.label} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {src.used
                          ? <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                          : <XCircle className="w-4 h-4 text-slate-600 flex-shrink-0" />
                        }
                        <span className={`text-sm ${src.used ? 'text-slate-300' : 'text-slate-600'}`}>
                          {src.label}
                        </span>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                        src.used
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          : 'bg-slate-500/10 text-slate-600 border border-slate-700/50'
                      }`}>
                        {src.used ? 'Used' : src.configured ? 'Error' : 'Unavailable'}
                      </span>
                    </div>
                  ))}

                  {/* VirusTotal engine counts if available */}
                  {result.totalEngines > 0 && (
                    <div className="mt-3 pt-3 border-t border-white/5 grid grid-cols-4 gap-2 text-center">
                      <div>
                        <p className="text-red-400 font-bold text-sm">{result.maliciousCount}</p>
                        <p className="text-slate-600 text-xs">Malicious</p>
                      </div>
                      <div>
                        <p className="text-orange-400 font-bold text-sm">{result.suspiciousCount}</p>
                        <p className="text-slate-600 text-xs">Suspicious</p>
                      </div>
                      <div>
                        <p className="text-emerald-400 font-bold text-sm">{result.safeCount}</p>
                        <p className="text-slate-600 text-xs">Clean</p>
                      </div>
                      <div>
                        <p className="text-slate-400 font-bold text-sm">{result.undetectedCount}</p>
                        <p className="text-slate-600 text-xs">Undetected</p>
                      </div>
                    </div>
                  )}
                </div>
              </Card>

              {/* ── Card 3: Technical Checks ──────────────────────────────── */}
              <Card title={t('Technical Checks', 'तकनीकी जाँच')} icon={Eye}>
                {result.technicalChecks.length > 0 ? (
                  <div className="space-y-2">
                    {result.technicalChecks.map((chk, i) => (
                      <div key={i} className="flex items-center gap-3">
                        {chk.passed
                          ? <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                          : <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                        }
                        <div className="flex-1 min-w-0">
                          <span className={`text-sm font-medium ${chk.passed ? 'text-slate-300' : 'text-red-300'}`}>
                            {chk.check}
                          </span>
                          <span className="text-slate-600 text-xs"> — {chk.detail}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-600 text-sm">No detailed checks available.</p>
                )}
              </Card>

              {/* ── Card 4: Threat Indicators ─────────────────────────────── */}
              {result.threatIndicators.length > 0 && (
                <Card title={t('Threat Indicators', 'खतरे के संकेतक')} icon={AlertTriangle}>
                  <ul className="space-y-2">
                    {result.threatIndicators.map((ind, i) => (
                      <li key={i} className="flex items-start gap-2.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-orange-400 flex-shrink-0 mt-1.5" />
                        <span className="text-slate-300 text-sm">{ind}</span>
                      </li>
                    ))}
                  </ul>
                </Card>
              )}

              {/* ── Card 5: Score Breakdown (collapsible) ─────────────────── */}
              {result.scoreFactors.length > 0 && (
                <CollapsibleCard title={t('Score Breakdown', 'स्कोर विवरण')} icon={Zap} defaultOpen={false}>
                  <div className="space-y-2">
                    {result.scoreFactors.map((f, i) => (
                      <div key={i} className="flex items-center justify-between">
                        <span className="text-slate-400 text-sm">{f.factor}</span>
                        <span className={`text-sm font-mono font-bold ${
                          f.impact > 0 ? 'text-red-400' : 'text-emerald-400'
                        }`}>
                          {f.impact > 0 ? `+${f.impact}` : f.impact}
                        </span>
                      </div>
                    ))}
                    <div className="flex items-center justify-between border-t border-white/5 pt-2 mt-2">
                      <span className="text-slate-300 text-sm font-medium">Total Risk Score</span>
                      <span className="text-white font-bold font-mono">{result.riskScore} / 100</span>
                    </div>
                  </div>
                </CollapsibleCard>
              )}

              {/* ── Card 6: Domain Information ───────────────────────────── */}
              <Card title={t('Domain Information', 'डोमेन जानकारी')} icon={Globe}>
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-white/5 rounded-xl p-3">
                    <p className="text-slate-500 text-xs mb-1">{t('Hostname', 'होस्टनाम')}</p>
                    <p className="text-white text-sm font-mono truncate">{result.hostname}</p>
                  </div>
                  <div className="bg-white/5 rounded-xl p-3">
                    <p className="text-slate-500 text-xs mb-1">{t('Protocol', 'प्रोटोकॉल')}</p>
                    <div className="flex items-center gap-1.5">
                      {result.normalizedUrl.startsWith('https')
                        ? <Lock className="w-3 h-3 text-emerald-400" />
                        : <Unlock className="w-3 h-3 text-orange-400" />
                      }
                      <span className={`text-sm font-medium ${
                        result.normalizedUrl.startsWith('https') ? 'text-emerald-400' : 'text-orange-400'
                      }`}>
                        {result.normalizedUrl.startsWith('https') ? 'HTTPS' : 'HTTP'}
                      </span>
                    </div>
                  </div>
                  <div className="bg-white/5 rounded-xl p-3">
                    <div className="flex items-center gap-1 mb-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      <p className="text-slate-500 text-xs">{t('Domain Age', 'डोमेन आयु')}</p>
                    </div>
                    <p className={`text-sm font-medium ${
                      result.domainAge.toLowerCase().includes('unknown') ? 'text-slate-400'
                      : result.domainAge.toLowerCase().includes('day') || result.domainAge.toLowerCase().includes('new')
                        ? 'text-red-400' : 'text-emerald-400'
                    }`}>
                      {result.domainAge}
                    </p>
                  </div>
                  <div className="bg-white/5 rounded-xl p-3">
                    <p className="text-slate-500 text-xs mb-1">{t('Connection', 'कनेक्शन')}</p>
                    <p className={`text-sm font-medium ${
                      result.invalidDomain ? 'text-red-400' : 'text-emerald-400'
                    }`}>
                      {result.connectionStatus || (result.invalidDomain ? 'Unreachable' : 'Reachable')}
                    </p>
                  </div>
                </div>
              </Card>

              {/* ── Card 7: Recommendations ──────────────────────────────── */}
              <Card title={t('Recommendations', 'सिफारिशें')} icon={Shield}>
                <ul className="space-y-2">
                  {result.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2.5">
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5 ${
                        ['Dangerous', 'Suspicious'].includes(result.overallStatus)
                          ? 'bg-orange-400'
                          : 'bg-cyan-400'
                      }`} />
                      <span className="text-slate-300 text-sm">{rec}</span>
                    </li>
                  ))}
                </ul>
              </Card>

            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
