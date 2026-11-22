import { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Upload,
  Link,
  AlertTriangle,
  CheckCircle,
  ShieldCheck,
  AlertCircle,
  Loader2,
  Eye,
  Info,
  Sparkles,
  Camera,
  Cpu,
  Layers,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  LucideIcon,
} from 'lucide-react';
import { useLang } from '../context/LanguageContext';
import { detectDeepfake } from '../api';
import { recordUserActivity } from '../lib/userStats';
import { GlassmorphicPanel, CyberGrid } from '../components/premium/PremiumUI';

export type DecisiveVerdict =
  | 'AUTHENTIC_PROVENANCE'
  | 'LIKELY_AUTHENTIC'
  | 'AI_GENERATED'
  | 'LIKELY_AI'
  | 'MANIPULATED'
  | 'UNCERTAIN';

type InputMode = 'upload' | 'link';

interface DetectionSignalRow {
  signal: string;
  score: number;
  detail: string;
}

interface DebugAnalysis {
  file_name: string;
  mime_type: string;
  file_size: number;
  sha256: string;
  original_image_dimensions: [number, number];
  original_image_format: string;
  metadata_fields_detected: number;
  c2pa_fields_detected: {
    c2pa_available?: boolean;
    c2pa_detected?: boolean;
    c2pa_valid?: boolean;
    claim_generator?: string | null;
    is_generative_ai?: boolean;
    is_camera_capture?: boolean;
    actions?: string[];
  };
  xmp_fields_detected: string[];
  exif_fields_detected: string[];
  camera_manufacturer: string | null;
  camera_model: string | null;
  software_tag: string | null;
  creator_tool: string | null;
  generator_tool: string | null;
  clip_available: boolean;
  clip_status: string;
  clip_raw_real_scores: Record<string, number>;
  clip_raw_ai_scores: Record<string, number>;
  clip_aggregate_score?: number | null;
  clip_confidence?: number | null;
  specialized_detector: {
    model_name: string;
    available: boolean;
    score: number;
    confidence: number;
    device: string;
    inference_time_ms?: number;
  };
  every_forensic_signal_score: Record<string, number>;
  forensic_aggregate_score: number;
  camera_provenance_score: number;
  ai_provenance_score: number;
  metadata_integrity_score: number;
  credential_validity_score: number;
  provenance_conflict_score: number;
  provenance_score: number;
  final_fusion_score: number;
  final_verdict: string;
  final_confidence: number;
  device: string;
  decision_hierarchy_level_triggered: string;
  verdict_reason: string;
  google_provenance: {
    google_provenance_detected: boolean;
    synthid_watermark_status: string;
    synthid_verification_api: string;
    details: string;
  };
}

interface AnalysisResult {
  verdict: DecisiveVerdict;
  verdictColor: string;
  verdictReason: string;
  confidence: number;
  aiProbability: number;
  manipulationRisk: number;
  confidenceLevel?: string;
  detectionSignals: DetectionSignalRow[];
  metadataStatus?: string;
  suspiciousIndicators: string[];
  reason: string;
  manipulation: string[];
  action: string;
  context?: string;
  debugAnalysis?: DebugAnalysis;
  provenance?: Record<string, unknown> | null;
}

const decisiveVerdictConfigs: Record<
  DecisiveVerdict,
  {
    icon: LucideIcon;
    color: string;
    border: string;
    bg: string;
    label: string;
    labelHi: string;
    badge: string;
    bar: string;
  }
> = {
  AUTHENTIC_PROVENANCE: {
    icon: ShieldCheck,
    color: 'text-emerald-400',
    border: 'border-emerald-500/40',
    bg: 'bg-emerald-500/10 border-emerald-500/30',
    label: 'AUTHENTIC PROVENANCE',
    labelHi: 'सत्यापित कैमरा प्रामाणिकता',
    badge: 'bg-emerald-500/20 border-emerald-400 text-emerald-300 shadow-glow-sm',
    bar: 'from-emerald-600 to-teal-400',
  },
  LIKELY_AUTHENTIC: {
    icon: CheckCircle,
    color: 'text-teal-400',
    border: 'border-teal-500/30',
    bg: 'bg-teal-500/10 border-teal-500/30',
    label: 'LIKELY AUTHENTIC',
    labelHi: 'संभवतः प्रामाणिक फोटो',
    badge: 'bg-teal-500/15 border-teal-400/50 text-teal-300',
    bar: 'from-teal-500 to-cyan-400',
  },
  AI_GENERATED: {
    icon: Sparkles,
    color: 'text-red-400',
    border: 'border-red-500/40',
    bg: 'bg-red-500/10 border-red-500/30',
    label: 'AI GENERATED',
    labelHi: 'AI जनित (सत्यापित साक्ष्य)',
    badge: 'bg-red-500/20 border-red-400 text-red-300 shadow-glow-sm',
    bar: 'from-red-600 to-orange-500',
  },
  LIKELY_AI: {
    icon: AlertTriangle,
    color: 'text-orange-400',
    border: 'border-orange-500/30',
    bg: 'bg-orange-500/10 border-orange-500/30',
    label: 'LIKELY AI GENERATED',
    labelHi: 'संभवतः AI जनित छवि',
    badge: 'bg-orange-500/15 border-orange-400/50 text-orange-300',
    bar: 'from-orange-500 to-amber-400',
  },
  MANIPULATED: {
    icon: AlertCircle,
    color: 'text-amber-400',
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/10 border-amber-500/30',
    label: 'MANIPULATED / SPLICED',
    labelHi: 'छेड़छाड़ / संशोधित छवि',
    badge: 'bg-amber-500/15 border-amber-400/50 text-amber-300',
    bar: 'from-amber-500 to-yellow-400',
  },
  UNCERTAIN: {
    icon: Info,
    color: 'text-slate-300',
    border: 'border-slate-500/30',
    bg: 'bg-slate-500/10 border-slate-500/30',
    label: 'UNCERTAIN / INCONCLUSIVE',
    labelHi: 'अनिर्णीत / पुनः जाँच आवश्यक',
    badge: 'bg-slate-500/15 border-slate-400/50 text-slate-300',
    bar: 'from-slate-500 to-slate-400',
  },
};

export default function DeepfakeDetector() {
  const MAX_FILE_MB = 25;
  const [mode, setMode] = useState<InputMode>('upload');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');
  const [showDebug, setShowDebug] = useState(false);
  const [copiedDebug, setCopiedDebug] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const { t } = useLang();

  async function analyze() {
    if (mode === 'upload' && !file) return;
    if (mode === 'link' && !url.trim()) return;
    if (mode === 'upload' && file && file.size > MAX_FILE_MB * 1024 * 1024) {
      setError(`File size exceeds ${MAX_FILE_MB}MB. Please upload a smaller file.`);
      return;
    }
    setLoading(true);
    setResult(null);
    setError('');
    try {
      const data = await detectDeepfake(mode === 'upload' ? file : url.trim());
      const rawVerdict = String(data.verdict || 'UNCERTAIN').toUpperCase();

      let normalizedVerdict: DecisiveVerdict = 'UNCERTAIN';
      if (rawVerdict === 'AUTHENTIC_PROVENANCE') normalizedVerdict = 'AUTHENTIC_PROVENANCE';
      else if (rawVerdict === 'LIKELY_AUTHENTIC' || rawVerdict === 'REAL') normalizedVerdict = 'LIKELY_AUTHENTIC';
      else if (rawVerdict === 'AI_GENERATED') normalizedVerdict = 'AI_GENERATED';
      else if (rawVerdict === 'LIKELY_AI' || rawVerdict === 'LIKELY AI-GENERATED' || rawVerdict === 'FAKE')
        normalizedVerdict = 'LIKELY_AI';
      else if (rawVerdict === 'MANIPULATED') normalizedVerdict = 'MANIPULATED';
      else normalizedVerdict = 'UNCERTAIN';

      const calibRaw = Number(data.confidence_percent ?? data.confidenceScore ?? data.confidence ?? 0.50);
      const calibrationPct = Math.round(calibRaw <= 1 ? calibRaw * 100 : calibRaw);

      const signals: DetectionSignalRow[] = Array.isArray(data.detectionSignals)
        ? data.detectionSignals.map((row: { signal?: string; score?: number; detail?: string }) => ({
            signal: String(row.signal ?? ''),
            score: Number(row.score ?? 0),
            detail: String(row.detail ?? ''),
          }))
        : [];

      const indicators: string[] = Array.isArray(data.suspiciousIndicators)
        ? data.suspiciousIndicators.map((x: unknown) => String(x))
        : [];
      const chips = [...(data.findings || []), ...indicators].filter(Boolean);

      recordUserActivity(
        'deepfake',
        normalizedVerdict === 'AI_GENERATED' || normalizedVerdict === 'LIKELY_AI'
          ? 'dangerous'
          : normalizedVerdict === 'AUTHENTIC_PROVENANCE' || normalizedVerdict === 'LIKELY_AUTHENTIC'
            ? 'safe'
            : 'suspicious',
        data.details || 'Deepfake analysis completed.'
      );

      setResult({
        verdict: normalizedVerdict,
        verdictColor: data.verdict_color || 'yellow',
        verdictReason: data.verdict_reason || data.reason || 'Hierarchical media authentication completed.',
        confidence: Math.min(100, Math.max(0, calibrationPct)),
        aiProbability: Math.min(100, Math.max(0, Number(data.aiProbability ?? 0))),
        manipulationRisk: Math.min(100, Math.max(0, Number(data.manipulationRisk ?? 0))),
        confidenceLevel: typeof data.confidenceLevel === 'string' ? data.confidenceLevel : undefined,
        detectionSignals: signals,
        metadataStatus: typeof data.metadataStatus === 'string' ? data.metadataStatus : undefined,
        suspiciousIndicators: indicators,
        reason: data.details || data.verdict_reason || 'Multi-stage authentication complete.',
        manipulation: chips.length ? chips : data.recommendations || [],
        action: t(
          data.englishSummary || 'Review evidence before publishing or sharing.',
          data.hindiSummary || 'साझा करने से पहले साक्ष्यों की समीक्षा करें।'
        ),
        context: `${data.details} Source: ${data.mediaUrl || (file?.name || 'unknown')}`,
        debugAnalysis: data.debugAnalysis as DebugAnalysis | undefined,
        provenance: data.provenance,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Deepfake analysis failed.');
    } finally {
      setLoading(false);
    }
  }

  const copyDebugJson = () => {
    if (result?.debugAnalysis) {
      navigator.clipboard.writeText(JSON.stringify(result.debugAnalysis, null, 2));
      setCopiedDebug(true);
      setTimeout(() => setCopiedDebug(false), 2000);
    }
  };

  const vConfig = result ? decisiveVerdictConfigs[result.verdict] : null;

  return (
    <div className="min-h-screen bg-veyron-navy pt-16 relative overflow-hidden">
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-32 right-1/3 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />
        <CyberGrid />
      </div>

      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-12 relative z-10">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }} className="mb-12">
          <div className="flex items-center gap-4 mb-6">
            <motion.div whileHover={{ scale: 1.1, rotate: 10 }} className="w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-500 to-pink-500 p-4 flex items-center justify-center shadow-cyber-lg">
              <Eye className="w-8 h-8 text-white" />
            </motion.div>
            <div>
              <h1 className="font-grotesk text-4xl font-bold text-white mb-2">{t('Deepfake & Media Authenticator', 'डीपफेक एवं मीडिया प्रमाणीकरण')}</h1>
              <p className="text-lg text-slate-300">{t('Cryptographic Provenance • C2PA • Swin ML • Image Forensics', 'क्रिप्टोग्राफ़िक मूल • C2PA • Swin ML • इमेज फॉरेंसिक्स')}</p>
            </div>
          </div>

          <GlassmorphicPanel hover={false} className="!p-4 !bg-blue-500/10 !border-blue-500/30">
            <div className="flex gap-4">
              <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
              <div className="text-sm text-slate-300 space-y-1">
                <p className="font-semibold text-blue-300">{t('Strict 6-Level Authentication Hierarchy', 'सख्त 6-स्तरीय प्रमाणीकरण पदानुक्रम')}</p>
                <p>
                  {t(
                    'Level 1: Verified C2PA / Content Credentials & Certified Camera Provenance | Level 2: Generator Metadata Signatures | Level 3: Specialized Synthetic AI Model (umm-maybe Swin-Base) | Level 4: Physical Sensor Noise & Compression ELA | Level 5: CLIP Prompt Secondary | Level 6: Ambiguous cases return UNCERTAIN.',
                    'स्तर 1: C2PA क्रेडेंशियल्स व कैमरा मूल | स्तर 2: जनरेटर मेटाडेटा हस्ताक्षर | स्तर 3: विशेष AI डिटेक्टर (Swin-Base) | स्तर 4: फॉरेंसिक सेंसर नॉइज़ व ELA | स्तर 5: CLIP द्वितीयक | स्तर 6: अस्पष्ट मामलों में अनिर्णीत (UNCERTAIN)।'
                  )}
                </p>
                <p className="text-yellow-300 text-xs mt-2">
                  {t(
                    '🛡️ Original uploaded bytes are preserved intact for provenance inspection before any CV resizing occurs.',
                    '🛡️ CV रीसाइज़िंग से पहले मूल अपलोड बाइट्स को अप्रभावित रखकर मेटाडेटा व C2PA विश्लेषण किया जाता है।'
                  )}
                </p>
                <p className="text-slate-400 text-xs mt-1 border-t border-slate-700/50 pt-1.5">
                  {t(
                    '🔬 Detector Scope: Specialized in detecting generative AI (diffusion models, GANs, and synthetic generation artifacts) and cryptographic provenance. Conventional 2D editing (manual splicing/cloning) lacks diffusion noise signatures and may not trigger generative AI thresholds.',
                    '🔬 डिटेक्टर दायरा: जनरेटिव AI (डिफ्यूजन, GAN, सिंथेटिक निर्माण) और क्रिप्टोग्राफ़िक मूल की पहचान में विशेषज्ञ। सामान्य 2D संपादन (मैनुअल स्प्लिसिंग) में डिफ्यूजन नॉइज़ नहीं होता।'
                  )}
                </p>
              </div>
            </div>
          </GlassmorphicPanel>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="mb-8">
          <div className="inline-flex gap-2 p-1 bg-white/5 border border-cyan-500/20 rounded-xl">
            {[
              { mode: 'upload' as const, icon: Upload, en: 'Upload File', hi: 'फ़ाइल अपलोड' },
              { mode: 'link' as const, icon: Link, en: 'Paste URL', hi: 'URL डालें' },
            ].map((item) => (
              <motion.button
                key={item.mode}
                onClick={() => {
                  setMode(item.mode);
                  setResult(null);
                }}
                whileHover={{ scale: 1.05 }}
                className={`flex items-center gap-2 px-6 py-2.5 rounded-lg text-sm font-semibold transition-all ${
                  mode === item.mode
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-glow'
                    : 'text-slate-400 hover:text-cyan-300'
                }`}
              >
                <item.icon className="w-4 h-4" />
                {t(item.en, item.hi)}
              </motion.button>
            ))}
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="mb-8">
          <GlassmorphicPanel hover={true} delay={0.2} className="!p-8">
            {mode === 'upload' ? (
              <div>
                <input
                  ref={fileRef}
                  type="file"
                  accept="image/jpeg,image/png,image/webp,video/mp4,video/quicktime"
                  className="hidden"
                  onChange={(e) => {
                    setFile(e.target.files?.[0] || null);
                    setResult(null);
                    setError('');
                  }}
                />
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  onClick={() => fileRef.current?.click()}
                  className="w-full border-2 border-dashed border-cyan-500/40 hover:border-cyan-400 rounded-2xl p-12 text-center transition-all group relative overflow-hidden"
                >
                  <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 via-transparent to-purple-500/5 group-hover:from-cyan-500/10 transition-all" />
                  <div className="relative space-y-4">
                    <motion.div animate={{ y: [0, -10, 0] }} transition={{ duration: 3, repeat: Infinity }} className="flex justify-center">
                      <Upload className="w-12 h-12 text-cyan-400 group-hover:text-cyan-300 transition-colors" />
                    </motion.div>
                    {file ? (
                      <div>
                        <p className="text-white font-semibold text-lg">{file.name}</p>
                        <p className="text-slate-400 text-sm mt-2">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                      </div>
                    ) : (
                      <div>
                        <p className="text-cyan-300 font-semibold text-lg">{t('Drag image or video here', 'छवि या वीडियो यहां लाएं')}</p>
                        <p className="text-slate-400 text-sm mt-2">{t('or click to browse', 'या चुनने के लिए क्लिक करें')}</p>
                        <p className="text-slate-500 text-xs mt-3">
                          {t('Still images preferred — JPG • PNG • WEBP (max 25MB)', 'स्थिर छवि अनुशंसित — JPG • PNG • WEBP (अधिकतम 25MB)')}
                        </p>
                      </div>
                    )}
                  </div>
                </motion.button>
              </div>
            ) : (
              <div className="space-y-3">
                <label className="text-slate-300 text-sm font-semibold block">{t('Paste image or video URL', 'छवि या वीडियो URL डालें')}</label>
                <input
                  type="url"
                  value={url}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    setResult(null);
                  }}
                  placeholder="https://example.com/image.jpg"
                  className="w-full bg-veyron-navy border border-cyan-500/20 rounded-xl px-4 py-3 text-white text-sm placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 focus:shadow-glow-sm transition-all"
                />
              </div>
            )}
          </GlassmorphicPanel>
        </motion.div>

        <motion.button
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          onClick={analyze}
          disabled={loading || (mode === 'upload' ? !file : !url.trim())}
          whileHover={{ scale: 1.02 }}
          className="w-full flex items-center justify-center gap-3 py-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:from-slate-600 disabled:to-slate-700 disabled:cursor-not-allowed text-white font-bold text-base rounded-xl transition-all shadow-cyber-lg hover:shadow-cyber-xl"
        >
          {loading ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              {t('Executing Hierarchical Forensic Screen...', 'पदानुक्रमिक फॉरेंसिक स्क्रीन निष्पादन हो रहा है...')}
            </>
          ) : (
            <>
              <Sparkles className="w-5 h-5" />
              {t('Authenticate Media', 'मीडिया प्रमाणीकरण करें')}
            </>
          )}
        </motion.button>

        {error && (
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-4 text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            {error}
          </motion.p>
        )}

        {result && vConfig && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }} className="mt-12 space-y-6">
            {/* Top Verdict Panel */}
            <GlassmorphicPanel hover={false}>
              <div className="flex items-start justify-between mb-6">
                <div className="flex items-start gap-4">
                  <div className={`p-3 rounded-xl border ${vConfig.bg}`}>
                    <vConfig.icon className={`w-8 h-8 ${vConfig.color}`} />
                  </div>
                  <div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border text-sm font-bold uppercase ${vConfig.badge}`}>
                        {vConfig.label}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        Model Confidence: <strong className="text-white">{result.confidence}%</strong>
                      </span>
                    </div>

                    <h2 className={`font-grotesk text-2xl font-bold ${vConfig.color} mt-2 mb-2`}>
                      {t(vConfig.label, vConfig.labelHi)}
                    </h2>
                    <p className="text-slate-300 text-sm mb-4 leading-relaxed">{result.verdictReason}</p>

                    <div className="space-y-3">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-xs uppercase tracking-wide text-slate-500 w-44 shrink-0">
                          {t('AI Probability Index', 'AI संभाव्यता सूचकांक')}
                        </span>
                        <div className="flex-1 min-w-[140px] h-2.5 bg-slate-800/50 rounded-full overflow-hidden border border-orange-500/20">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${result.aiProbability}%` }}
                            transition={{ duration: 1.2, ease: 'easeOut' }}
                            className="h-full rounded-full bg-gradient-to-r from-orange-600 to-amber-400"
                          />
                        </div>
                        <span className="text-orange-300 font-mono text-sm w-12">{result.aiProbability}%</span>
                      </div>

                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-xs uppercase tracking-wide text-slate-500 w-44 shrink-0">
                          {t('Manipulation / Splicing', 'छेड़छाड़ / संपादन जोखिम')}
                        </span>
                        <div className="flex-1 min-w-[140px] h-2.5 bg-slate-800/50 rounded-full overflow-hidden border border-violet-500/20">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${result.manipulationRisk}%` }}
                            transition={{ duration: 1.2, ease: 'easeOut', delay: 0.08 }}
                            className="h-full rounded-full bg-gradient-to-r from-violet-600 to-fuchsia-400"
                          />
                        </div>
                        <span className="text-violet-300 font-mono text-sm w-12">{result.manipulationRisk}%</span>
                      </div>

                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-xs uppercase tracking-wide text-slate-500 w-44 shrink-0">
                          {t('Ensemble Signal Score', 'एंसेंबल सिग्नल स्कोर')}
                        </span>
                        <div className="flex-1 min-w-[140px] h-2.5 bg-slate-800/50 rounded-full overflow-hidden border border-cyan-500/20">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${result.confidence}%` }}
                            transition={{ duration: 1.2, ease: 'easeOut', delay: 0.15 }}
                            className={`h-full rounded-full bg-gradient-to-r ${vConfig.bar}`}
                          />
                        </div>
                        <span className="text-cyan-300 font-mono text-sm w-12">{result.confidence}%</span>
                      </div>
                      <p className="text-[11px] text-slate-500 italic mt-2">
                        * {t('Confidence scores represent heuristic signal alignment across stages, not calibrated statistical probabilities.', 'विश्वसनीयता स्कोर विभिन्न स्तरों के बीच सिग्नल संरेखण दर्शाते हैं, सांख्यिकीय संभावना नहीं।')}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Provenance & Hardware Breakdown (Level 1 & 2) */}
              <div className="border-t border-slate-700/50 pt-5 mt-4">
                <div className="flex items-center gap-2 mb-3">
                  <Camera className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-semibold text-cyan-300 uppercase tracking-wider">
                    {t('Level 1 & 2: Provenance & Hardware Inspection', 'स्तर 1 व 2: मूल व हार्डवेयर निरीक्षण')}
                  </h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 bg-slate-900/60 border border-slate-700/60 rounded-xl space-y-1">
                    <span className="text-slate-400 font-medium">{t('C2PA Content Credentials', 'C2PA कंटेंट क्रेडेंशियल्स')}</span>
                    <p className="font-semibold text-white">
                      {result.debugAnalysis?.c2pa_fields_detected?.c2pa_detected ? (
                        <span className="text-emerald-400">
                          Manifest Present ({result.debugAnalysis.c2pa_fields_detected.c2pa_valid ? 'Cryptographically Valid' : 'Invalid/Tampered'})
                        </span>
                      ) : (
                        <span className="text-slate-400">Not Present / Stripped</span>
                      )}
                    </p>
                    {result.debugAnalysis?.c2pa_fields_detected?.claim_generator && (
                      <p className="text-[11px] text-slate-400 truncate">
                        Claim: {result.debugAnalysis.c2pa_fields_detected.claim_generator}
                      </p>
                    )}
                  </div>

                  <div className="p-3 bg-slate-900/60 border border-slate-700/60 rounded-xl space-y-1">
                    <span className="text-slate-400 font-medium">{t('Camera Hardware EXIF', 'कैमरा हार्डवेयर EXIF')}</span>
                    <p className="font-semibold text-white truncate">
                      {result.debugAnalysis?.camera_manufacturer || result.debugAnalysis?.camera_model ? (
                        <span className="text-emerald-400">
                          {result.debugAnalysis.camera_manufacturer || ''} {result.debugAnalysis.camera_model || ''}
                        </span>
                      ) : (
                        <span className="text-slate-400">No Camera EXIF (Stripped/Web)</span>
                      )}
                    </p>
                    <p className="text-[11px] text-slate-400">
                      EXIF tags: {result.debugAnalysis?.exif_fields_detected?.length || 0} fields
                    </p>
                  </div>

                  <div className="p-3 bg-slate-900/60 border border-slate-700/60 rounded-xl space-y-1">
                    <span className="text-slate-400 font-medium">{t('Google AI / SynthID', 'गूगल AI / SynthID')}</span>
                    <p className="font-semibold text-white">
                      {result.debugAnalysis?.google_provenance?.google_provenance_detected ? (
                        <span className="text-red-400">Google AI Provenance Confirmed</span>
                      ) : (
                        <span className="text-slate-400">Not Detected</span>
                      )}
                    </p>
                    <p className="text-[10px] text-slate-500">
                      SynthID local API: Unavailable locally (Requires Google Cloud API)
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3 text-[11px]">
                  <div className="bg-slate-950/40 p-2 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block">Camera Prov Score:</span>
                    <span className="font-mono text-cyan-300 font-bold">
                      {result.debugAnalysis?.camera_provenance_score?.toFixed(3) ?? '0.000'}
                    </span>
                  </div>
                  <div className="bg-slate-950/40 p-2 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block">AI Prov Score:</span>
                    <span className="font-mono text-orange-300 font-bold">
                      {result.debugAnalysis?.ai_provenance_score?.toFixed(3) ?? '0.000'}
                    </span>
                  </div>
                  <div className="bg-slate-950/40 p-2 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block">Metadata Integrity:</span>
                    <span className="font-mono text-emerald-300 font-bold">
                      {result.debugAnalysis?.metadata_integrity_score?.toFixed(3) ?? '0.500'}
                    </span>
                  </div>
                  <div className="bg-slate-950/40 p-2 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block">Provenance Conflict:</span>
                    <span className="font-mono text-amber-300 font-bold">
                      {result.debugAnalysis?.provenance_conflict_score?.toFixed(3) ?? '0.000'}
                    </span>
                  </div>
                </div>
              </div>

              {/* AI Detector Breakdown (Level 3 & 5) */}
              <div className="border-t border-slate-700/50 pt-5 mt-4">
                <div className="flex items-center gap-2 mb-3">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-purple-300 uppercase tracking-wider">
                    {t('Level 3 & 5: Vision ML & Classifier Models', 'स्तर 3 व 5: विज़न ML व क्लासिफायर')}
                  </h3>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-purple-950/20 border border-purple-500/30 rounded-xl space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-purple-200">
                        Primary: {result.debugAnalysis?.specialized_detector?.model_name || 'umm-maybe/AI-image-detector'}
                      </span>
                      <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40">
                        {result.debugAnalysis?.specialized_detector?.device || 'cpu'}
                      </span>
                    </div>
                    <p className="text-slate-300">
                      Trained synthetic classifier (Swin-Base fine-tuned for AI vs Real generation).
                    </p>
                    <div className="flex items-center justify-between font-mono pt-1 text-slate-300">
                      <span>
                        AI Probability:{' '}
                        <strong className="text-orange-400">
                          {((result.debugAnalysis?.specialized_detector?.score ?? 0.5) * 100).toFixed(1)}%
                        </strong>
                      </span>
                      <span>
                        Latency: {result.debugAnalysis?.specialized_detector?.inference_time_ms ?? 0}ms
                      </span>
                    </div>
                  </div>

                  <div className="p-3 bg-slate-900/60 border border-slate-700/60 rounded-xl space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200">Secondary: CLIP ViT-B/32 (Prompt Match)</span>
                      <span
                        className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded ${
                          result.debugAnalysis?.clip_available
                            ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                            : 'bg-red-500/20 text-red-300 border border-red-500/40'
                        }`}
                      >
                        {result.debugAnalysis?.clip_status || 'MODEL_UNAVAILABLE'}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px]">
                      Demoted to secondary signal (weight ≤ 0.05). Uncalibrated for synthetic separation.
                    </p>
                    <div className="flex items-center justify-between font-mono pt-1 text-slate-300">
                      <span>
                        CLIP Score:{' '}
                        <strong className="text-cyan-300">
                          {result.debugAnalysis?.clip_available && typeof result.debugAnalysis?.clip_aggregate_score === 'number'
                            ? `${(result.debugAnalysis.clip_aggregate_score * 100).toFixed(1)}%`
                            : 'N/A (Unavailable)'}
                        </strong>
                      </span>
                      <span>
                        Confidence:{' '}
                        {result.debugAnalysis?.clip_available && typeof result.debugAnalysis?.clip_confidence === 'number'
                          ? `${(result.debugAnalysis.clip_confidence * 100).toFixed(1)}%`
                          : 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Forensic Signal Breakdown (Level 4) */}
              {result.detectionSignals.length > 0 && (
                <div className="border-t border-slate-700/50 pt-5 mt-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Layers className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-sm font-semibold text-cyan-300 uppercase tracking-wider">
                      {t('Level 4: Heuristic Forensic Signal Breakdown', 'स्तर 4: फॉरेंसिक संकेत विवरण')}
                    </h3>
                  </div>
                  <div className="rounded-xl border border-slate-700/60 overflow-hidden text-xs">
                    <table className="w-full text-left border-collapse">
                      <thead className="bg-slate-900 text-slate-400 uppercase tracking-wide text-[11px]">
                        <tr>
                          <th className="px-3 py-2 font-semibold">{t('Signal', 'संकेत')}</th>
                          <th className="px-3 py-2 font-semibold w-24">{t('Score', 'स्कोर')}</th>
                          <th className="px-3 py-2 font-semibold">{t('Physical / Statistical Meaning', 'भौतिक व सांख्यिकीय अर्थ')}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {result.detectionSignals.map((row, i) => (
                          <tr key={`${row.signal}-${i}`} className="bg-slate-950/40 hover:bg-slate-900/60">
                            <td className="px-3 py-2 text-slate-200 font-mono">{row.signal}</td>
                            <td className="px-3 py-2 text-amber-300/90 font-mono">{row.score.toFixed(3)}</td>
                            <td className="px-3 py-2 text-slate-400">{row.detail}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Manipulation / Highlights */}
              {result.manipulation.length > 0 && (
                <div className="mt-4 pt-4 border-t border-slate-700/50">
                  <p className="text-cyan-300 text-xs font-semibold mb-2">{t('Detected Indicators', 'चिन्हित संकेत')}</p>
                  <div className="flex flex-wrap gap-2">
                    {result.manipulation.map((m, i) => (
                      <span
                        key={i}
                        className="px-2.5 py-1 bg-slate-800/80 border border-cyan-500/25 text-cyan-100/90 text-xs rounded-lg font-medium"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Action Banner */}
              <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-4 mt-5">
                <p className="text-cyan-300 text-xs font-semibold uppercase tracking-wider mb-1">
                  {t('Authentication Recommendation', 'प्रमाणीकरण अनुशंसा')}
                </p>
                <p className="text-slate-300 text-sm">{result.action}</p>
              </div>
            </GlassmorphicPanel>

            {/* Developer / Debug Object Collapsible Panel */}
            {result.debugAnalysis && (
              <GlassmorphicPanel hover={false} className="!p-5 border-cyan-500/30">
                <div className="flex items-center justify-between cursor-pointer" onClick={() => setShowDebug(!showDebug)}>
                  <div className="flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-cyan-400" />
                    <div>
                      <h4 className="text-sm font-bold text-white font-grotesk tracking-wide">
                        Developer Inspection (33-Field Raw Debug Analysis Object)
                      </h4>
                      <p className="text-xs text-slate-400">
                        SHA-256: <code className="text-cyan-300 font-mono">{result.debugAnalysis.sha256.substring(0, 24)}...</code> • Hierarchy Level: <span className="text-purple-300">{result.debugAnalysis.decision_hierarchy_level_triggered}</span>
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyDebugJson();
                      }}
                      className="px-2.5 py-1 bg-white/5 hover:bg-white/10 text-cyan-300 text-xs rounded-lg border border-cyan-500/30 flex items-center gap-1 transition-all"
                    >
                      {copiedDebug ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedDebug ? 'Copied' : 'Copy JSON'}
                    </button>
                    {showDebug ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
                  </div>
                </div>

                {showDebug && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} className="mt-4 pt-4 border-t border-slate-700/50 space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">FILE NAME</span>
                        <span className="text-white truncate block">{result.debugAnalysis.file_name}</span>
                      </div>
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">MIME / FORMAT</span>
                        <span className="text-cyan-300 block">{result.debugAnalysis.mime_type} ({result.debugAnalysis.original_image_format})</span>
                      </div>
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">FILE SIZE / DIMS</span>
                        <span className="text-white block">{(result.debugAnalysis.file_size / 1024).toFixed(1)} KB ({result.debugAnalysis.original_image_dimensions.join('×')})</span>
                      </div>
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">EXECUTION DEVICE</span>
                        <span className="text-emerald-300 block uppercase font-bold">{result.debugAnalysis.device}</span>
                      </div>
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">FINAL FUSION SCORE</span>
                        <span className="text-amber-300 block font-bold">{result.debugAnalysis.final_fusion_score.toFixed(4)}</span>
                      </div>
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                        <span className="text-slate-500 block text-[10px]">FINAL CONFIDENCE</span>
                        <span className="text-cyan-300 block font-bold">{result.debugAnalysis.final_confidence.toFixed(4)}</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-xs font-semibold text-slate-400 block mb-1">Full Debug Analysis Payload:</span>
                      <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-[11px] font-mono text-cyan-200 overflow-x-auto max-h-72">
                        {JSON.stringify(result.debugAnalysis, null, 2)}
                      </pre>
                    </div>
                  </motion.div>
                )}
              </GlassmorphicPanel>
            )}
          </motion.div>
        )}
      </div>
    </div>
  );
}
