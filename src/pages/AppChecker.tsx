import { useState } from 'react';
import { Smartphone, AlertTriangle, CheckCircle, XCircle, Loader2, Shield, Info, AlertCircle } from 'lucide-react';
import { useLang } from '../context/LanguageContext';
import { checkApp } from '../api';

type Verdict = 'official' | 'suspicious' | 'fake' | null;

interface Permission {
  name: string;
  dangerous: boolean;
  reason: string;
}

interface AppResult {
  verdict: Verdict;
  appName: string;
  developer: string;
  developerVerified: boolean;
  rating: number | null;
  downloads: string | null;
  permissions: Permission[];
  risks: string[];
  isGovApp: boolean;
  govMatchesDatabase: boolean;
  playStoreSource: boolean;
  action: string;
  summary: string;
  uninstallSteps?: string[];
  officialAlternative?: string;
  officialPlayLink?: string | null;
  playStoreLink?: string | null;
  lookupStatus?: string;
}

const GOV_APPS: Record<string, { official: string; developer: string; pkg: string; link: string }> = {
  'aadhaar': { official: 'Aadhaar', developer: 'UIDAI', pkg: 'in.gov.uidai.pehchaan', link: 'https://play.google.com/store/apps/details?id=in.gov.uidai.pehchaan' },
  'maadhaar': { official: 'mAadhaar', developer: 'UIDAI', pkg: 'in.gov.uidai.mAadhaarPlus', link: 'https://play.google.com/store/apps/details?id=in.gov.uidai.mAadhaarPlus' },
  'umang': { official: 'UMANG', developer: 'National e-Governance Division', pkg: 'in.gov.umang.negd.g2c', link: 'https://play.google.com/store/apps/details?id=in.gov.umang.negd.g2c' },
  'digilocker': { official: 'DigiLocker', developer: 'National e-Governance Division', pkg: 'com.digilocker.android', link: 'https://play.google.com/store/apps/details?id=com.digilocker.android' },
  'irctc': { official: 'IRCTC Rail Connect', developer: 'CRIS', pkg: 'cris.org.in.prs.ima', link: 'https://play.google.com/store/apps/details?id=cris.org.in.prs.ima' },
  'bhim': { official: 'BHIM', developer: 'National Payments Corporation of India', pkg: 'in.org.npci.upiapp', link: 'https://play.google.com/store/apps/details?id=in.org.npci.upiapp' },
  'pm kisan': { official: 'PM Kisan', developer: 'Ministry of Agriculture', pkg: 'com.nic.pmkisan', link: 'https://play.google.com/store/apps/details?id=com.nic.pmkisan' },
  'cowin': { official: 'CoWIN', developer: 'Ministry of Health and Family Welfare', pkg: 'com.cowin.gov.in', link: 'https://play.google.com/store/apps/details?id=com.cowin.gov.in' },
  'aarogya setu': { official: 'Aarogya Setu', developer: 'National Informatics Centre', pkg: 'nic.goi.aarogyasetu', link: 'https://play.google.com/store/apps/details?id=nic.goi.aarogyasetu' },
};

const verdictConfig = {
  official: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30', label: 'OFFICIAL & VERIFIED', labelHi: 'आधिकारिक और सत्यापित' },
  suspicious: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', label: 'SUSPICIOUS', labelHi: 'संदिग्ध' },
  fake: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', label: 'FAKE / UNVERIFIED', labelHi: 'नकली / असत्यापित' },
};

export default function AppChecker() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AppResult | null>(null);
  const [error, setError] = useState('');
  const { t } = useLang();

  async function check() {
    if (!query.trim()) return;
    setLoading(true);
    setResult(null);
    setError('');
    try {
      const data = await checkApp(query.trim());
      const permissions: Permission[] = (data.permissions || []).map((p: { permission: string; riskLevel?: string; explanation?: string }) => ({
        name: p.permission,
        dangerous: p.riskLevel === 'high' || p.riskLevel === 'medium',
        reason: p.explanation || 'Permission review suggested.',
      }));

      // Use real data from the API — do NOT hardcode developer/rating/downloads
      const developer = data.developer || null;
      const rating = typeof data.rating === 'number' ? data.rating : null;
      const downloads = data.installs || data.downloads || null;
      const playStoreSource = !!(developer && developer !== 'Official Government Source');

      setResult({
        verdict: data.verdict,
        appName: data.appName || query.trim(),
        developer: developer || (playStoreSource ? 'Unknown Developer' : 'Gov Database'),
        developerVerified: data.verdict === 'official',
        rating,
        downloads,
        permissions,
        risks: Array.isArray(data.risks) ? data.risks : [],
        isGovApp: Array.isArray(data.officialAlternatives) && data.officialAlternatives.length > 0,
        govMatchesDatabase: data.verdict !== 'suspicious' && data.verdict !== 'fake',
        playStoreSource,
        action: data.recommendation || 'Review app details carefully.',
        summary: data.englishSummary || '',
        uninstallSteps: data.verdict === 'fake' ? [
          'Settings → Apps → Select the app',
          'Revoke all permissions first',
          'Uninstall the app',
          'Change any passwords entered in the app from a trusted device',
        ] : undefined,
        officialAlternative: data.officialAlternatives?.[0]?.name,
        officialPlayLink: typeof data.officialAlternatives?.[0]?.playStoreLink === 'string' && data.officialAlternatives[0].playStoreLink.startsWith('https://play.google.com/')
          ? data.officialAlternatives[0].playStoreLink
          : null,
        playStoreLink: typeof data.playStoreLink === 'string' && data.playStoreLink.startsWith('https://play.google.com/')
          ? data.playStoreLink
          : null,
        lookupStatus: data.lookupStatus,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check app. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  const vConf = result?.verdict ? verdictConfig[result.verdict] : null;

  return (
    <div className="min-h-screen bg-[#060d1f] pt-16">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-12">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <div className="w-12 h-12 rounded-2xl bg-green-500/10 border border-green-500/20 flex items-center justify-center">
            <Smartphone className="w-6 h-6 text-green-400" />
          </div>
          <div>
            <h1 className="font-['Space_Grotesk'] text-3xl font-bold text-white">{t('App Authenticity Checker', 'ऐप प्रामाणिकता चेकर')}</h1>
            <p className="text-slate-500">{t('Verify apps before or after installing', 'इंस्टॉल करने से पहले या बाद में ऐप जांचें')}</p>
          </div>
        </div>

        {/* Info */}
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 mb-8 flex gap-3">
          <Info className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
          <p className="text-slate-400 text-sm">
            {t(
              'Fake government apps are a major scam vector in India. Always verify app developers before installing. Our database includes 50+ official government apps.',
              'नकली सरकारी ऐप्स भारत में बड़ा खतरा हैं। इंस्टॉल करने से पहले डेवलपर सत्यापित करें।'
            )}
          </p>
        </div>

        {/* Input */}
        <div className="bg-[#0a1628] border border-slate-700/50 rounded-2xl p-6 mb-6">
          <label className="text-slate-400 text-sm font-medium block mb-2">
            {t('Enter app name or paste Play Store link', 'ऐप का नाम या Play Store लिंक डालें')}
          </label>
          <div className="relative">
            <Smartphone className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
            <input
              type="text"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setResult(null); }}
              onKeyDown={(e) => e.key === 'Enter' && check()}
              placeholder={t('e.g., UMANG, DigiLocker, mAadhaar', 'जैसे UMANG, DigiLocker, mAadhaar')}
              className="w-full bg-[#060d1f] border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-white text-sm placeholder-slate-600 focus:outline-none focus:border-green-500/50 transition-colors"
            />
          </div>
          <p className="text-slate-600 text-xs mt-2">
            {t('Try: Aadhaar, IRCTC, BHIM, PM Kisan, Income Tax, DigiLocker, UMANG', 'आज़माएं: Aadhaar, IRCTC, BHIM, DigiLocker')}
          </p>
        </div>

        <button
          onClick={check}
          disabled={loading || !query.trim()}
          className="w-full flex items-center justify-center gap-3 py-4 bg-green-500 hover:bg-green-400 disabled:bg-slate-700 disabled:cursor-not-allowed text-[#060d1f] font-bold text-base rounded-xl transition-all"
        >
          {loading ? (
            <><Loader2 className="w-5 h-5 animate-spin" />{t('Checking app...', 'ऐप जांच हो रही है...')}</>
          ) : (
            <><Shield className="w-5 h-5" />{t('Check App', 'ऐप जांचें')}</>
          )}
        </button>
        {error && <p className="mt-3 text-sm text-red-300">{error}</p>}

        {/* Results */}
        {result && vConf && (
          <div className={`mt-8 border rounded-2xl p-6 ${vConf.bg}`}>
            <div className="flex items-start gap-4 mb-6 pb-6 border-b border-white/10">
              <vConf.icon className={`w-10 h-10 ${vConf.color} flex-shrink-0`} />
              <div className="flex-1 min-w-0">
                <p className={`font-['Space_Grotesk'] text-2xl font-bold ${vConf.color}`}>
                  {t(vConf.label, vConf.labelHi)}
                </p>
                <p className="text-white font-medium mt-0.5 truncate">{result.appName}</p>
                <div className="flex items-center flex-wrap gap-x-2 gap-y-1 mt-1">
                  <span className="text-slate-400 text-xs">{t('Developer:', 'डेवलपर:')} {result.developer}</span>
                  {result.developerVerified && (
                    <span className="flex items-center gap-1 text-green-400 text-xs">
                      <CheckCircle className="w-3 h-3" /> {t('Verified', 'सत्यापित')}
                    </span>
                  )}
                </div>
                {result.playStoreSource && (
                  <span className="inline-block mt-1.5 text-[10px] text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 rounded px-1.5 py-0.5">
                    {t('Live Play Store data', 'लाइव Play Store डेटा')}
                  </span>
                )}
              </div>
            </div>

            {/* App stats — rendered from real API data */}
            <div className="grid grid-cols-3 gap-3 mb-6">
              <div className="bg-white/5 rounded-xl p-3 text-center">
                <p className="text-white font-bold">
                  {result.rating !== null ? `${result.rating.toFixed(1)}/5` : t('N/A', 'N/A')}
                </p>
                <p className="text-slate-500 text-xs">{t('Rating', 'रेटिंग')}</p>
              </div>
              <div className="bg-white/5 rounded-xl p-3 text-center">
                <p className="text-white font-bold text-xs">{result.downloads ?? t('N/A', 'N/A')}</p>
                <p className="text-slate-500 text-xs">{t('Installs', 'इंस्टॉल')}</p>
              </div>
              <div className="bg-white/5 rounded-xl p-3 text-center">
                <p className={`font-bold text-sm ${result.govMatchesDatabase ? 'text-green-400' : 'text-slate-400'}`}>
                  {result.isGovApp ? (result.govMatchesDatabase ? t('Gov ✓', 'सरकारी ✓') : t('No Match', 'नहीं मिला')) : t('N/A', 'N/A')}
                </p>
                <p className="text-slate-500 text-xs">{t('Gov DB', 'सरकारी DB')}</p>
              </div>
            </div>

            {/* Risk flags from backend */}
            {result.risks.length > 0 && result.risks[0] !== 'No major red flags detected.' && (
              <div className="mb-6 space-y-2">
                {result.risks.map((risk, i) => (
                  <div key={i} className="flex items-start gap-2 bg-red-500/10 border border-red-500/20 rounded-xl px-3 py-2">
                    <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                    <p className="text-red-300 text-sm">{risk}</p>
                  </div>
                ))}
              </div>
            )}

            {/* Permissions */}
            {result.permissions.length > 0 && (
              <div className="mb-6">
                <p className="text-slate-300 text-sm font-medium mb-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-orange-400" />
                  {t('Permission Audit', 'अनुमति ऑडिट')} ({result.permissions.length} {t('total', 'कुल')})
                </p>
                <div className="space-y-2">
                  {result.permissions.map((p, i) => (
                    <div key={i} className={`rounded-xl p-3 flex items-start gap-3 ${p.dangerous ? 'bg-red-500/10 border border-red-500/20' : 'bg-white/5'}`}>
                      {p.dangerous ? (
                        <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                      ) : (
                        <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      )}
                      <div>
                        <p className={`text-sm font-mono font-medium ${p.dangerous ? 'text-red-300' : 'text-slate-300'}`}>{p.name}</p>
                        <p className="text-slate-500 text-xs mt-0.5">{p.reason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Uninstall Steps */}
            {result.uninstallSteps && (
              <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-4">
                <p className="text-red-400 font-semibold text-sm mb-2">{t('Uninstall Immediately:', 'तुरंत अनइंस्टॉल करें:')}</p>
                <ol className="space-y-1">
                  {result.uninstallSteps.map((s, i) => (
                    <li key={i} className="text-slate-400 text-sm flex gap-2">
                      <span className="text-red-400 font-bold flex-shrink-0">{i + 1}.</span>{s}
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {/* Official Store Listing for the Checked Application */}
            {result.playStoreLink && result.verdict === 'official' && (
              <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 mb-4">
                <p className="text-green-400 font-semibold text-sm mb-1">{t('Official Store Listing:', 'आधिकारिक स्टोर लिस्टिंग:')}</p>
                <p className="text-white font-medium">{result.appName}</p>
                <a href={result.playStoreLink} target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 mt-2 text-green-400 text-sm hover:text-green-300 transition-colors">
                  {t('Download from Google Play Store', 'Google Play Store से डाउनलोड करें')} →
                </a>
              </div>
            )}

            {/* Official Alternative (when unverified or suspicious) */}
            {result.officialAlternative && result.verdict !== 'official' && (
              <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 mb-4">
                <p className="text-green-400 font-semibold text-sm mb-1">{t('Official Alternative:', 'आधिकारिक विकल्प:')}</p>
                <p className="text-white font-medium">{result.officialAlternative}</p>
                {result.officialPlayLink && (
                  <a href={result.officialPlayLink} target="_blank" rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 mt-2 text-green-400 text-sm hover:text-green-300 transition-colors">
                    {t('Download Official Alternative from Play Store', 'Play Store से आधिकारिक विकल्प डाउनलोड करें')} →
                  </a>
                )}
              </div>
            )}

            {/* Unverified Play Store Search fallback when direct listing is unavailable */}
            {!result.playStoreLink && (
              <div className="bg-slate-800/40 border border-slate-700/40 rounded-xl p-4 mb-4">
                <p className="text-slate-400 text-xs mb-1">{t('Direct verified listing unavailable.', 'प्रत्यक्ष सत्यापित लिस्टिंग अनुपलब्ध है।')}</p>
                <a
                  href={`https://play.google.com/store/search?q=${encodeURIComponent(result.appName)}&c=apps`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-cyan-400 text-xs hover:text-cyan-300 transition-colors"
                >
                  {t('Search on Google Play (Unverified Search)', 'Google Play पर खोजें (अपुष्ट खोज)')} →
                </a>
              </div>
            )}

            <div className="bg-white/5 rounded-xl p-4 mb-6">
              <p className="text-cyan-400 text-sm font-semibold mb-1">{t('Action:', 'कार्रवाई:')}</p>
              <p className="text-slate-300 text-sm">{result.action}</p>
            </div>
            

          </div>
        )}

        {/* Gov App Quick Check */}
        <div className="mt-12">
          <h3 className="text-slate-300 font-semibold mb-4">{t('Quick Check: Official Government Apps', 'त्वरित जांच: आधिकारिक सरकारी ऐप्स')}</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {Object.entries(GOV_APPS).map(([key, val]) => (
              <button
                key={key}
                onClick={() => { setQuery(val.official); setResult(null); }}
                className="bg-[#0a1628] border border-slate-700/50 hover:border-green-500/20 rounded-xl p-3 text-left transition-all"
              >
                <p className="text-white text-sm font-medium">{val.official}</p>
                <p className="text-slate-600 text-xs mt-0.5">{val.developer.split(' ').slice(0, 2).join(' ')}</p>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
