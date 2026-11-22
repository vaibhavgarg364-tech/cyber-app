import { motion } from 'framer-motion';
import {
  Sparkles,
  ShieldCheck,
  PhoneCall,
  Globe,
  Fingerprint,
  Laptop,
  Check,
  ExternalLink,
} from 'lucide-react';
import { useLang } from '../context/LanguageContext';

export default function VeyronPro() {
  const { t, lang } = useLang();

  const proFeatures = [
    {
      icon: PhoneCall,
      titleEn: 'CyberSaathi Connect',
      titleHi: 'साइबरसाथी कनेक्ट',
      subtitleEn: 'Live AI Security Calling',
      subtitleHi: 'लाइव एआई सुरक्षा कॉलिंग',
      descEn:
        'Direct, conversational voice calling with CyberSaathi for real-time security guidance during active threats, scams, and digital emergencies.',
      descHi:
        'सक्रिय साइबर धोखाधड़ी, वित्तीय घोटालों और आपातकालीन परिस्थितियों के दौरान रीयल-टाइम सुरक्षा मार्गदर्शन के लिए साइबरसाथी के साथ प्रत्यक्ष संवादात्मक वॉयस कॉलिंग।',
      tag: 'Live Voice Advisory',
      status: 'COMING SOON',
      capabilitiesEn: [
        'Real-time AI voice conversations',
        'Natural Hindi and English interactions',
        'Interruptible two-way calling',
        'Personalized cybersecurity guidance',
        'Incident response assistance',
      ],
      capabilitiesHi: [
        'रीयल-टाइम एआई वॉइस वार्तालाप',
        'प्राकृतिक हिंदी एवं अंग्रेजी भाषा संवाद',
        'इंटरप्टिबल टू-वे कॉलिंग सपोर्ट',
        'व्यक्तिगत साइबर सुरक्षा मार्गदर्शन',
        'साइबर घटना त्वरित समाधान सहायता',
      ],
    },
    {
      icon: Globe,
      titleEn: 'Veyron Web Shield',
      titleHi: 'वेरॉन वेब शील्ड',
      subtitleEn: 'Proactive Browser Protection',
      subtitleHi: 'सक्रिय ब्राउज़र सुरक्षा',
      descEn:
        'Real-time browser extension that blocks malicious websites, prevents drive-by malware downloads, and inspects deceptive URLs before page execution.',
      descHi:
        'रीयल-टाइम ब्राउज़र एक्सटेंशन जो हानिकारक वेबसाइटों को ब्लॉक करता है, ड्राइव-बाय मैलवेयर डाउनलोड रोकता है, और वेबपेज लोड होने से पहले संदिग्ध यूआरएल का विश्लेषण करता है।',
      tag: 'Browser Defense',
      status: 'COMING SOON',
      capabilitiesEn: [
        'Browser extension protection',
        'Phishing and fake website detection',
        'High-confidence malicious website blocking',
        'Suspicious download-link warnings',
        'User-controlled protection settings',
        'Temporary site exceptions and protection controls',
      ],
      capabilitiesHi: [
        'सक्रिय ब्राउज़र एक्सटेंशन सुरक्षा',
        'फ़िशिंग एवं नकली वेबसाइट पहचान',
        'उच्च-सटीकता दुर्भावनापूर्ण वेबसाइट ब्लॉकिंग',
        'संदिग्ध डाउनलोड लिंक पूर्व-चेतावनी',
        'उपयोगकर्ता-नियंत्रित सुरक्षा सेटिंग्स',
        'अस्थायी अपवाद एवं सुरक्षा प्रबंधन',
      ],
    },
    {
      icon: Fingerprint,
      titleEn: 'Veyron Identity Watch',
      titleHi: 'वेरॉन आइडेंटिटी वॉच',
      subtitleEn: 'Personal Data Exposure Monitoring & Assisted Removal',
      subtitleHi: 'व्यक्तिगत डेटा प्रकटीकरण निगरानी एवं निष्कासन सहायता',
      descEn:
        'Continuous monitoring for compromised credentials, leaked phone numbers, and identity exposure across verified breach datasets and public broker directories.',
      descHi:
        'सत्यापित डेटा ब्रीच रिसाव और सार्वजनिक डेटा ब्रोकर सूचियों में समझौता किए गए पासवर्ड, लीक फ़ोन नंबर और पहचान प्रकटीकरण की निरंतर निगरानी।',
      tag: 'Identity Protection',
      status: 'COMING SOON',
      capabilitiesEn: [
        'Verified email and identity monitoring',
        'Relevant personal data exposure alerts',
        'Supported breach intelligence checks',
        'Automated removal requests with user authorization',
        'Removal status tracking and follow-ups',
        'Optional human specialist escalation for complex cases',
      ],
      capabilitiesHi: [
        'सत्यापित ईमेल एवं पहचान प्रकटीकरण निगरानी',
        'महत्वपूर्ण डेटा एक्सपोज़र तात्कालिक अलर्ट',
        'समर्थित ब्रीच इंटेलिजेंस विश्लेषण',
        'उपयोगकर्ता अधिकृत स्वचालित निष्कासन अनुरोध',
        'निष्कासन स्थिति ट्रैकिंग एवं फॉलो-अप्स',
        'जटिल मामलों हेतु वैकल्पिक सुरक्षा विशेषज्ञ सहायता',
      ],
    },
    {
      icon: Laptop,
      titleEn: 'Veyron Device Guard',
      titleHi: 'वेरॉन डिवाइस गार्ड',
      subtitleEn: 'Intelligent Device Security & Threat Monitoring',
      subtitleHi: 'बुद्धिमान उपकरण सुरक्षा एवं खतरा निगरानी',
      descEn:
        'Lightweight endpoint security monitor analyzing system integrity, suspicious background behaviors, and untrusted downloads on personal laptops and desktops.',
      descHi:
        'व्यक्तिगत लैपटॉप और डेस्कटॉप पर सिस्टम अखंडता, संदिग्ध पृष्ठभूमि गतिविधियों और अविश्वसनीय डाउनलोड्स का विश्लेषण करने वाला हल्का एंडपॉइंट सुरक्षा मॉनिटर।',
      tag: 'Endpoint Defense',
      status: 'COMING SOON',
      capabilitiesEn: [
        'Supported downloaded-file inspection',
        'Installed application security checks',
        'Antivirus and firewall health monitoring',
        'Suspicious file and application alerts',
        'Device security status insights',
        'User-authorized remediation and supported quarantine actions',
        'Network/Wi-Fi configuration security insights where platform APIs permit',
      ],
      capabilitiesHi: [
        'डाउनलोड की गई फ़ाइलों की सुरक्षा जांच',
        'इंस्टॉल किए गए अनुप्रयोगों की सुरक्षा समीक्षा',
        'एंटीवायरस एवं फ़ायरवॉल स्थिति निगरानी',
        'संदिग्ध फ़ाइल एवं ऐप तात्कालिक चेतावनी',
        'उपकरण समग्र सुरक्षा स्वास्थ्य अंतर्दृष्टि',
        'उपयोगकर्ता अधिकृत समाधान एवं क्वारंटाइन कार्रवाई',
        'प्लेटफ़ॉर्म समर्थित नेटवर्क/वाई-फ़ाई कॉन्फ़िगरेशन सुरक्षा समीक्षा',
      ],
    },
  ];

  const comparisonRows = [
    {
      featureEn: 'Deepfake & Synthetic Media Detection (CUDA FP32)',
      featureHi: 'डीपफेक एवं सिंथेटिक मीडिया पहचान (CUDA FP32)',
      free: true,
      pro: true,
      proNote: 'Full Web Scanner & Local CUDA Acceleration',
    },
    {
      featureEn: 'Phishing Link Scanner & SSRF Shield',
      featureHi: 'फ़िशिंग लिंक स्कैनर एवं SSRF शील्ड',
      free: true,
      pro: true,
      proNote: 'Web Scanner + Browser Shield Integration',
    },
    {
      featureEn: 'Zero-Trust QR Shield (UPI, URL, Wi-Fi, Text)',
      featureHi: 'ज़ीरो-ट्रस्ट क्यूआर शील्ड (UPI, URL, वाई-फाई)',
      free: true,
      pro: true,
      proNote: 'Web Scanner, File Upload & Camera Viewfinder',
    },
    {
      featureEn: 'CyberSaathi Bilingual AI & Legal Advisory',
      featureHi: 'साइबरसाथी द्विभाषी एआई एवं कानूनी सलाह',
      free: true,
      pro: true,
      proNote: 'Web Chatbot + CyberSaathi Connect Live Calling',
    },
    {
      featureEn: 'Email Breach & Credential Exposure Checker',
      featureHi: 'ईमेल ब्रीच एवं क्रेडेंशियल एक्सपोजर चेकर',
      free: true,
      pro: true,
      proNote: 'On-Demand Lookup + Continuous Identity Watch',
    },
    {
      featureEn: 'App Authenticity & Play Store Integrity Checker',
      featureHi: 'ऐप प्रामाणिकता एवं प्ले स्टोर सत्यापन',
      free: true,
      pro: true,
      proNote: 'Web Registry Lookup + Device Guard Endpoint Inspection',
    },
    {
      featureEn: 'Cybercrime Complaint Generator (36 States/UTs)',
      featureHi: 'साइबर अपराध शिकायत प्रारूप (36 राज्य/केंद्र शासित प्रदेश)',
      free: true,
      pro: true,
      proNote: 'Official Format Export & Evidence Dossier',
    },
    {
      featureEn: 'CyberSaathi Connect (Live AI Voice Calling)',
      featureHi: 'साइबरसाथी कनेक्ट (लाइव एआई वॉयस कॉलिंग)',
      free: false,
      pro: true,
      proNote: 'Coming Soon • Two-Way Emergency Voice Calling',
    },
    {
      featureEn: 'Veyron Web Shield (Proactive Browser Extension)',
      featureHi: 'वेरॉन वेब शील्ड (सक्रिय ब्राउज़र एक्सटेंशन)',
      free: false,
      pro: true,
      proNote: 'Coming Soon • Real-Time Malicious Website Blocking',
    },
    {
      featureEn: 'Veyron Identity Watch (Continuous Exposure Monitoring & Removal)',
      featureHi: 'वेरॉन आइडेंटिटी वॉच (निरंतर एक्सपोजर निगरानी एवं निष्कासन)',
      free: false,
      pro: true,
      proNote: 'Coming Soon • Automated Breach & Broker Removal',
    },
    {
      featureEn: 'Veyron Device Guard (Endpoint Security & Health Monitoring)',
      featureHi: 'वेरॉन डिवाइस गार्ड (एंडपॉइंट सुरक्षा एवं स्वास्थ्य निगरानी)',
      free: false,
      pro: true,
      proNote: 'Coming Soon • System Posture & Integrity Alerts',
    },
  ];

  return (
    <div className="min-h-screen bg-[#060d1f] pt-16 pb-24 text-white">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

        {/* ─── Hero Section ─── */}
        <div className="text-center py-12 sm:py-16 relative">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-gradient-to-r from-cyan-500/20 via-purple-500/20 to-blue-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-semibold uppercase tracking-wider mb-6 shadow-lg shadow-cyan-500/10">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            {t('Personal Cyber Protection • Roadmap Preview', 'व्यक्तिगत साइबर सुरक्षा • रोडमैप पूर्वावलोकन')}
          </div>

          <h1 className="font-['Space_Grotesk'] text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white mb-6 leading-tight">
            {t('Veyron Pro: Personal Security & Identity Defense', 'वेरॉन प्रो: व्यक्तिगत सुरक्षा एवं डिजिटल पहचान सुरक्षा')}
          </h1>

          <p className="text-slate-300 text-base sm:text-lg max-w-3xl mx-auto leading-relaxed mb-8">
            {t(
              'A transparent architectural preview of Veyron’s upcoming personal protection suite. Designed for individuals and families to monitor device security posture, track identity exposure across verified breach dumps, and receive guided remediation.',
              'वेरॉन के आगामी व्यक्तिगत सुरक्षा सुइट का पारदर्शी पूर्वावलोकन। अपने डिवाइस की सुरक्षा स्थिति जांचने, ब्रीच डेटाबेस में लीक क्रेडेंशियल की निगरानी करने और सटीक समाधान प्राप्त करने के लिए डिज़ाइन किया गया।'
            )}
          </p>

          {/* Citizen Safety Commitment Badge */}
          <div className="max-w-2xl mx-auto p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs sm:text-sm flex items-start sm:items-center gap-3 text-left">
            <ShieldCheck className="w-6 h-6 text-emerald-400 flex-shrink-0" />
            <div>
              <span className="font-bold text-white block">
                {t('Core Protection is 100% Free Forever for Every Citizen', 'नागरिकों के लिए बुनियादी सुरक्षा सदैव 100% निःशुल्क')}
              </span>
              <p className="text-slate-300 mt-0.5 text-xs">
                {t(
                  'Every core security tool—Deepfake Detection, Phishing Link Scanner, QR Shield, CyberSaathi Assistant, Email Breach Checker, App Authenticity Checker, and Complaint Generator—is and will always remain completely free and open for every individual.',
                  'डीपफेक डिटेक्टर, लिंक स्कैनर, क्यूआर शील्ड, साइबरसाथी, ईमेल ब्रीच चेकर और शिकायत प्रारूप जैसे सभी आवश्यक उपकरण हमेशा हर नागरिक के लिए पूरी तरह निःशुल्क रहेंगे।'
                )}
              </p>
            </div>
          </div>
        </div>

        {/* ─── Planned Personal Pro Capabilities Grid (4 Finalized Features in 2x2 Grid) ─── */}
        <div className="mb-20">
          <div className="text-center mb-12">
            <h2 className="font-['Space_Grotesk'] text-2xl sm:text-3xl font-bold tracking-tight text-white mb-3">
              {t('Four Next-Generation Defense Pillars', 'चार अगली पीढ़ी के सुरक्षा स्तंभ')}
            </h2>
            <p className="text-slate-400 text-sm max-w-xl mx-auto">
              {t(
                'Honest previews of personal cybersecurity capabilities currently in active engineering. Each module is labeled COMING SOON and validated against real threat models.',
                'सक्रिय विकास में चल रहे व्यक्तिगत सुरक्षा उपकरणों का पारदर्शी पूर्वावलोकन। प्रत्येक मॉड्यूल "शीघ्र आ रहा है" (COMING SOON) के रूप में चिह्नित है।'
              )}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {proFeatures.map((feat, idx) => {
              const capabilities = lang === 'en' ? feat.capabilitiesEn : feat.capabilitiesHi;
              return (
                <motion.div
                  key={idx}
                  whileHover={{ y: -4 }}
                  className="bg-white/5 backdrop-blur-xl border border-slate-700/60 rounded-2xl p-6 sm:p-8 flex flex-col justify-between hover:border-cyan-500/50 transition-all duration-300 shadow-xl"
                >
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                        <feat.icon className="w-6 h-6" />
                      </div>
                      <span className="px-2.5 py-1 rounded-full text-[10px] font-bold tracking-wider uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        {feat.status}
                      </span>
                    </div>

                    <span className="text-[11px] font-mono font-semibold text-cyan-400 uppercase tracking-wider block mb-1">
                      {t(feat.subtitleEn, feat.subtitleHi)}
                    </span>
                    <h3 className="font-['Space_Grotesk'] font-bold text-xl text-white mb-3 leading-snug">
                      {t(feat.titleEn, feat.titleHi)}
                    </h3>
                    <p className="text-slate-300 text-xs sm:text-sm leading-relaxed mb-6">
                      {t(feat.descEn, feat.descHi)}
                    </p>

                    {/* Planned Capabilities Bullet Points */}
                    <div className="space-y-2.5 mb-6 pt-4 border-t border-slate-800/80">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                        {t('Planned Capabilities', 'योजनाबद्ध क्षमताएं')}
                      </div>
                      <ul className="space-y-2">
                        {capabilities.map((cap, cIdx) => (
                          <li key={cIdx} className="flex items-start gap-2.5 text-xs text-slate-300">
                            <div className="w-4 h-4 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 flex-shrink-0 mt-0.5">
                              <Check className="w-2.5 h-2.5" />
                            </div>
                            <span>{cap}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                    <span className="font-mono text-[11px] text-slate-400">{feat.tag}</span>
                    <span className="text-cyan-400 font-semibold flex items-center gap-1">
                      {t('Planned Milestone', 'योजनाबद्ध मील का पत्थर')} →
                    </span>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>

        {/* ─── Free vs Pro Comparison Matrix ─── */}
        <div className="mb-20">
          <div className="text-center mb-10">
            <h2 className="font-['Space_Grotesk'] text-2xl sm:text-3xl font-bold tracking-tight text-white mb-2">
              {t('Transparent Capability Comparison', 'पारदर्शी क्षमता तुलना तालिका')}
            </h2>
            <p className="text-slate-400 text-sm">
              {t('No hidden barriers. Core consumer protection is 100% free forever.', 'नागरिकों की सुरक्षा के लिए कोई कृत्रिम दीवार नहीं। कोर सुरक्षा सदैव निःशुल्क।')}
            </p>
          </div>

          <div className="bg-white/5 backdrop-blur-xl border border-slate-700/60 rounded-2xl overflow-hidden shadow-2xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 text-xs font-semibold uppercase tracking-wider">
                    <th className="py-4 px-6">{t('Feature / Capability', 'क्षमता / सुविधा')}</th>
                    <th className="py-4 px-6 text-center w-48">
                      <span className="text-white block font-bold">{t('Veyron Free (Citizen)', 'वेरॉन निःशुल्क (नागरिक)')}</span>
                      <span className="text-emerald-400 text-[10px]">{t('100% Free Forever', 'सदैव निःशुल्क')}</span>
                    </th>
                    <th className="py-4 px-6 text-center w-56 bg-cyan-500/10 border-l border-r border-cyan-500/20">
                      <span className="text-cyan-300 block font-bold">{t('Veyron Pro (Personal Suite)', 'वेरॉन प्रो (पर्सनल सुइट)')}</span>
                      <span className="text-amber-400 text-[10px]">{t('Coming Soon Roadmap', 'आगामी रोडमैप')}</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {comparisonRows.map((row, idx) => (
                    <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3.5 px-6 font-medium text-slate-200">
                        {t(row.featureEn, row.featureHi)}
                      </td>
                      <td className="py-3.5 px-6 text-center">
                        {row.free ? (
                          <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/10 text-emerald-400 mx-auto">
                            <Check className="w-4 h-4" />
                          </div>
                        ) : (
                          <span className="text-slate-600 font-mono text-xs">—</span>
                        )}
                      </td>
                      <td className="py-3.5 px-6 text-center bg-cyan-500/5 border-l border-r border-cyan-500/20">
                        <div className="flex flex-col items-center gap-0.5">
                          <div className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-300">
                            <Check className="w-4 h-4" />
                          </div>
                          {row.proNote && (
                            <span className="text-[10px] text-slate-400">{row.proNote}</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* ─── Honest Early Access & GitHub Tracking ─── */}
        <div className="bg-gradient-to-r from-cyan-900/30 via-slate-900/80 to-purple-900/30 border border-cyan-500/30 rounded-3xl p-8 sm:p-12 text-center relative overflow-hidden shadow-2xl">
          <div className="relative z-10 max-w-2xl mx-auto">
            <h2 className="font-['Space_Grotesk'] text-3xl font-bold text-white mb-3">
              {t('Transparent Engineering & Open Roadmap', 'पारदर्शी इंजीनियरिंग एवं खुला रोडमैप')}
            </h2>
            <p className="text-slate-300 text-sm mb-6 leading-relaxed">
              {t(
                'Veyron Pro is actively under development. We do not use fake registration forms or artificial waitlists. You can track all source code progress, feature commits, and release notes directly on our public GitHub repository.',
                'वेरॉन प्रो सक्रिय विकास के अधीन है। हम कृत्रिम वेटलिस्ट का उपयोग नहीं करते हैं। आप सभी प्रगति, कमिट्स और रिलीज़ नोट्स सीधे हमारे सार्वजनिक गिटहब रिपॉजिटरी पर देख सकते हैं।'
              )}
            </p>

            <a
              href="https://github.com/vaibhavgarg364-tech/Veyron-v1"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-sm transition-all shadow-lg shadow-cyan-500/20"
            >
              <ExternalLink className="w-4 h-4" />
              {t('View Veyron-v1 on GitHub', 'GitHub पर Veyron-v1 देखें')}
            </a>

            <p className="text-[11px] text-slate-500 mt-4">
              {t(
                'Open-source and citizen-first. Hackathon 2026 release candidate.',
                'ओपन-सोर्स और नागरिक-प्रथम। हैकाथॉन 2026 रिलीज़ उम्मीदवार।'
              )}
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
