import { motion } from 'framer-motion';
import { Bot, Eye, FileText, Link2, Mail, Zap, AlertOctagon, Code2, HeartHandshake, Shield } from 'lucide-react';
import { useLang } from '../context/LanguageContext';
import CyberGlobe from '../components/3d/CyberGlobe.jsx';
import AmbientParticles from '../components/3d/AmbientParticles';
import { GlassmorphicPanel, HolographicText, PremiumButton, CyberBadge, CyberGrid } from '../components/premium/PremiumUI';
import DashboardStats from '../components/DashboardStats';

interface HomeProps {
  setPage: (page: string) => void;
  triggerEmergency: () => void;
}

const features = [
  { key: 'deepfake', icon: Eye, en: 'Deepfake Detector', hi: 'डीपफेक डिटेक्टर', descEn: 'Screen media for synthetic signals', descHi: 'मीडिया में संश्लेषित संकेतों की जांच', color: 'from-cyan-500 to-blue-600' },
  { key: 'scanner', icon: Link2, en: 'Link Scanner', hi: 'लिंक स्कैनर', descEn: 'Verify URL safety instantly', descHi: 'URL सुरक्षा तुरंत जांचें', color: 'from-blue-500 to-indigo-600' },
  { key: 'spam', icon: Mail, en: 'Email Checker', hi: 'ईमेल चेकर', descEn: 'Check breach exposure', descHi: 'ब्रीच एक्सपोजर जांचें', color: 'from-teal-500 to-cyan-600' },
  { key: 'complaints', icon: FileText, en: 'Complaint Hub', hi: 'शिकायत केंद्र', descEn: 'File official complaints', descHi: 'आधिकारिक शिकायत दर्ज करें', color: 'from-red-500 to-orange-600' },
  { key: 'app', icon: Code2, en: 'App Checker', hi: 'ऐप चेकर', descEn: 'Analyze app security', descHi: 'ऐप सुरक्षा विश्लेषण करें', color: 'from-purple-500 to-pink-600' },
  { key: 'rootcause', icon: Zap, en: 'Root Cause', hi: 'कारण विश्लेषण', descEn: 'Understand attack vectors', descHi: 'हमले के तरीके समझें', color: 'from-yellow-500 to-orange-600' },
];

const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.2,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: 'easeOut' } },
};

export default function Home({ setPage, triggerEmergency }: HomeProps) {
  const { t } = useLang();

  return (
    <div className="min-h-screen bg-veyron-navy text-white pt-16 relative overflow-hidden">
      {/* Ambient background effects */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl opacity-40" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl opacity-30" />
        <CyberGrid />
      </div>

      {/* HERO SECTION - Cinematic */}
      <section className="relative overflow-hidden px-4 sm:px-6 lg:px-8 py-20 max-w-7xl mx-auto z-10">
        <div className="absolute inset-0 opacity-40">
          <AmbientParticles count={90} />
        </div>
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="grid lg:grid-cols-[1fr_1.2fr] gap-12 items-center"
        >
          {/* Left: Text Content */}
          <motion.div
            variants={containerVariants}
            initial="hidden"
            animate="show"
            className="space-y-6 relative z-20"
          >
            <motion.div variants={itemVariants}>
              <CyberBadge variant="cyan">
                <Shield className="w-4 h-4" />
                {t('Open-Source Cyber Safety', 'ओपन-सोर्स साइबर सुरक्षा')}
              </CyberBadge>
            </motion.div>

            <motion.div variants={itemVariants}>
              <h1 className="font-grotesk text-5xl sm:text-6xl lg:text-7xl font-bold leading-tight">
                <HolographicText>
                  {t('Practical Cyber Safety Tools for Everyone', 'सभी के लिए व्यावहारिक साइबर सुरक्षा उपकरण')}
                </HolographicText>
              </h1>
            </motion.div>

            <motion.p variants={itemVariants} className="text-lg text-slate-300 max-w-xl leading-relaxed">
              {t(
                'Scan suspicious links, check email breaches, verify apps, and get step-by-step guidance during cyber incidents. Free, bilingual (Hindi/English), and built for Indian users.',
                'संदिग्ध लिंक स्कैन करें, ईमेल ब्रीच जांचें, ऐप्स सत्यापित करें, और साइबर घटनाओं के दौरान कदम-दर-कदम मार्गदर्शन पाएं। मुफ्त, द्विभाषी, भारतीय उपयोगकर्ताओं के लिए।'
              )}
            </motion.p>

            <motion.div variants={itemVariants} className="flex flex-wrap gap-4 pt-4">
              <PremiumButton
                variant="primary"
                onClick={triggerEmergency}
                className="!px-8 !py-4 text-base !text-white !bg-gradient-to-r !from-red-600 !to-rose-600 hover:!from-red-500 hover:!to-rose-500 !shadow-[0_12px_34px_rgba(220,38,38,0.35)]"
              >
                <AlertOctagon className="w-5 h-5 mr-2" />
                {t('Emergency Mode', 'आपातकाल मोड')}
              </PremiumButton>
              <PremiumButton
                variant="secondary"
                onClick={() => setPage('complaints')}
                className="!px-8 !py-4 text-base"
              >
                <FileText className="w-5 h-5 mr-2" />
                {t('File Complaint', 'शिकायत दर्ज करें')}
              </PremiumButton>
            </motion.div>
          </motion.div>

          {/* Right: 3D Globe */}
          <motion.div
            variants={itemVariants}
            className="relative h-96 lg:h-full min-h-[500px] rounded-3xl overflow-hidden border border-cyan-500/20 glass-dark shadow-cyber-xl"
          >
            <CyberGlobe />
            <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
              <div className="h-[74%] w-[74%] rounded-full border border-cyan-300/20 animate-pulse" />
              <div className="absolute h-[58%] w-[58%] rounded-full border border-cyan-400/20" />
            </div>
            <div className="absolute inset-0 rounded-3xl pointer-events-none" style={{
              boxShadow: 'inset 0 0 60px rgba(0, 224, 255, 0.1), 0 0 60px rgba(0, 224, 255, 0.15)',
            }} />
          </motion.div>
        </motion.div>

        <DashboardStats />
      </section>

      {/* FEATURE GRID - Premium Cards */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-20 max-w-7xl mx-auto z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="mb-12"
        >
          <h2 className="font-grotesk text-4xl font-bold mb-3">
            {t('Safety Tools', 'सुरक्षा उपकरण')}
          </h2>
          <p className="text-lg text-slate-400">
            {t('Check links, verify apps, scan emails, and report incidents', 'लिंक जांचें, ऐप्स सत्यापित करें, ईमेल स्कैन करें, और घटनाएं रिपोर्ट करें')}
          </p>
        </motion.div>

        <motion.div
          variants={containerVariants}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true }}
          className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {features.map((feature) => (
            <motion.button
              key={feature.key}
              variants={itemVariants}
              onClick={() => setPage(feature.key)}
              className="group text-left h-full"
            >
              <div className="relative rounded-2xl overflow-hidden h-full glass-dark border border-cyan-500/20 hover:border-cyan-500/50 p-6 transition-all duration-300 hover:shadow-cyber-lg hover:-translate-y-2">
                {/* Gradient background */}
                <div className={`absolute inset-0 bg-gradient-to-br ${feature.color} opacity-0 group-hover:opacity-5 transition-opacity`} />

                {/* Content */}
                <div className="relative space-y-4">
                  <div className={`w-14 h-14 rounded-xl bg-gradient-to-br ${feature.color} p-3 group-hover:scale-110 transition-transform`}>
                    <feature.icon className="w-full h-full text-white" />
                  </div>

                  <div>
                    <h3 className="font-grotesk text-xl font-bold text-white mb-2">
                      {t(feature.en, feature.hi)}
                    </h3>
                    <p className="text-sm text-slate-400">
                      {t(feature.descEn, feature.descHi)}
                    </p>
                  </div>

                  <div className="pt-4">
                    <div className="inline-flex items-center text-cyan-400 text-sm font-semibold group-hover:translate-x-2 transition-transform">
                      {t('Scan Now', 'अब स्कैन करें')} →
                    </div>
                  </div>
                </div>
              </div>
            </motion.button>
          ))}
        </motion.div>
      </section>

      {/* CYBERSAATHI SECTION - AI Assistant */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-20 max-w-7xl mx-auto z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
        >
          <GlassmorphicPanel className="!p-12 relative overflow-hidden" hover={false}>
            <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl -mr-32 -mt-32" />

            <div className="relative grid lg:grid-cols-[1fr_400px] gap-12 items-center">
              <div className="space-y-6">
                <CyberBadge variant="blue">
                  <Bot className="w-4 h-4" />
                  {t('Safety Assistant', 'सुरक्षा सहायक')}
                </CyberBadge>

                <h2 className="font-grotesk text-4xl font-bold">
                  {t('CyberSaathi: Your Safety Assistant', 'साइबरसाथी: आपका सुरक्षा सहायक')}
                </h2>

                <p className="text-lg text-slate-300">
                  {t(
                    'Step-by-step guidance during cyber incidents — UPI fraud, account hacks, phishing, sextortion. Helps you preserve evidence, report to authorities, and recover safely. Available in Hindi and English.',
                    'साइबर घटनाओं के दौरान कदम-दर-कदम मार्गदर्शन — UPI धोखाधड़ी, अकाउंट हैक, फिशिंग, सेक्सटॉर्शन। सबूत सुरक्षित रखने, अधिकारियों को रिपोर्ट करने और सुरक्षित पुनर्प्राप्ति में मदद करता है।'
                  )}
                </p>

                <ul className="space-y-3">
                  {[
                    { en: 'Incident-specific recovery steps', hi: 'घटना-विशिष्ट पुनर्प्राप्ति कदम' },
                    { en: 'Evidence preservation guidance', hi: 'सबूत सुरक्षित रखने का मार्गदर्शन' },
                    { en: 'Reporting & complaint assistance', hi: 'शिकायत और रिपोर्टिंग सहायता' },
                  ].map((item, idx) => (
                    <li key={idx} className="flex items-center gap-3 text-slate-300">
                      <div className="w-2 h-2 rounded-full bg-cyan-400" />
                      {t(item.en, item.hi)}
                    </li>
                  ))}
                </ul>

                <PremiumButton variant="primary" className="!mt-6">
                  <HeartHandshake className="w-5 h-5 mr-2" />
                  {t('Start Chat', 'चैट शुरू करें')}
                </PremiumButton>
              </div>

              {/* Holographic AI Icon */}
              <motion.div
                animate={{ float: [0, -10, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
                className="relative h-64 flex items-center justify-center"
              >
                <div className="relative w-40 h-40">
                  {/* Rotating rings */}
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 8, repeat: Infinity, ease: 'linear' }}
                    className="absolute inset-0 rounded-full border-2 border-transparent border-t-cyan-400 border-r-cyan-400"
                  />
                  <motion.div
                    animate={{ rotate: -360 }}
                    transition={{ duration: 12, repeat: Infinity, ease: 'linear' }}
                    className="absolute inset-2 rounded-full border-2 border-transparent border-b-blue-400 border-l-blue-400"
                  />

                  {/* Center AI Icon */}
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="relative">
                      <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-2xl opacity-20 blur-lg animate-pulse" />
                      <div className="relative bg-gradient-to-r from-cyan-500/20 to-blue-600/20 backdrop-blur-xl rounded-2xl p-6 border border-cyan-400/50">
                        <Bot className="w-16 h-16 text-cyan-300" />
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            </div>
          </GlassmorphicPanel>
        </motion.div>
      </section>

      {/* CTA FOOTER SECTION */}
      <section className="relative px-4 sm:px-6 lg:px-8 py-16 max-w-7xl mx-auto z-10">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="glass-dark rounded-3xl p-12 text-center border border-cyan-500/20 relative overflow-hidden"
        >
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-transparent to-blue-500/5" />
          <div className="relative space-y-6">
            <h2 className="font-grotesk text-4xl font-bold">
              {t('Stay Safe Online', 'ऑनलाइन सुरक्षित रहें')}
            </h2>
            <p className="text-lg text-slate-300 max-w-2xl mx-auto">
              {t(
                'Access all tools, emergency support, and guidance. No registration required. Always free.',
                'सभी उपकरण, आपातकालीन समर्थन और मार्गदर्शन का उपयोग करें। कोई पंजीकरण आवश्यक नहीं। हमेशा मुफ्त।'
              )}
            </p>
            <div className="flex flex-wrap justify-center gap-4">
              <PremiumButton variant="primary" onClick={() => setPage('scanner')}>
                {t('Start Scanning', 'स्कैनिंग शुरू करें')}
              </PremiumButton>
              <PremiumButton variant="secondary" onClick={() => setPage('awareness')}>
                {t('Learn More', 'अधिक जानें')}
              </PremiumButton>
            </div>
          </div>
        </motion.div>
      </section>
    </div>
  );
}
