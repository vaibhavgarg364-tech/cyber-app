import { useEffect, useState } from 'react';
import { LanguageProvider } from './context/LanguageContext';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import CyberSaathi from './components/CyberSaathi';
import Home from './pages/Home';
import Emergency from './pages/Emergency';
import DeepfakeDetector from './pages/DeepfakeDetector';
import LinkScanner from './pages/LinkScanner';
import SpamChecker from './pages/SpamChecker';
import AppChecker from './pages/AppChecker';
import RootCause from './pages/RootCause';
import ComplaintHub from './pages/ComplaintHub';
import Awareness from './pages/Awareness';
import QRShield from './pages/QRShield';
import VeyronPro from './pages/VeyronPro';
import CinematicBackground from './components/premium/CinematicBackground';

type Page = 'home' | 'emergency' | 'deepfake' | 'scanner' | 'spam' | 'app' | 'rootcause' | 'complaints' | 'awareness' | 'qrshield' | 'pro';

function parseHash(hashStr: string): Page | null {
  const clean = hashStr.replace(/^#\/?/, '').toLowerCase().trim();
  if (!clean) return null;
  if (clean === 'home' || clean === 'dashboard') return 'home';
  if (clean === 'deepfake' || clean === 'media') return 'deepfake';
  if (clean === 'scanner' || clean === 'links' || clean === 'link-scanner' || clean === 'linkscanner') return 'scanner';
  if (clean === 'qr' || clean === 'qr-shield' || clean === 'qrshield') return 'qrshield';
  if (clean === 'spam' || clean === 'email' || clean === 'breach' || clean === 'breaches') return 'spam';
  if (clean === 'app' || clean === 'apps' || clean === 'app-check' || clean === 'app-checker') return 'app';
  if (clean === 'rootcause' || clean === 'analysis') return 'rootcause';
  if (clean === 'complaints' || clean === 'complaint') return 'complaints';
  if (clean === 'awareness' || clean === 'learn') return 'awareness';
  if (clean === 'pro' || clean === 'veyronpro' || clean === 'enterprise') return 'pro';
  if (clean === 'emergency') return 'emergency';
  return null;
}

function AppContent() {
  const [page, setPage] = useState<Page>(() => {
    return parseHash(window.location.hash) || 'home';
  });
  const [chatOpen, setChatOpen] = useState(false);
  const [chatEmergency, setChatEmergency] = useState(false);

  function navigate(p: string) {
    const target = (parseHash(p) || p) as Page;
    setPage(target);
    if (window.location.hash.replace(/^#\/?/, '') !== target) {
      window.location.hash = `#/${target}`;
    }
    window.scrollTo({ top: 0 });
  }

  function triggerEmergency() {
    navigate('emergency');
  }

  function openEmergencyChat() {
    setChatEmergency(true);
    setChatOpen(true);
  }

  useEffect(() => {
    const handler = (evt: Event) => {
      const custom = evt as CustomEvent<{ page?: string }>;
      if (custom.detail?.page) {
        navigate(custom.detail.page);
      }
    };

    const onHashChange = () => {
      const parsed = parseHash(window.location.hash);
      if (parsed) setPage(parsed);
    };

    window.addEventListener('cybersaathi:navigate', handler as EventListener);
    window.addEventListener('hashchange', onHashChange);
    return () => {
      window.removeEventListener('cybersaathi:navigate', handler as EventListener);
      window.removeEventListener('hashchange', onHashChange);
    };
  }, []);

  const showNavAndFooter = page !== 'emergency';

  return (
    <div className="min-h-screen bg-[#060d1f] font-sans text-white relative overflow-x-hidden">
      <CinematicBackground />
      {showNavAndFooter && <Navbar currentPage={page} setPage={navigate} />}

      <main className="relative z-10">
        {page === 'home' && <Home setPage={navigate} triggerEmergency={triggerEmergency} />}
        {page === 'emergency' && <Emergency onOpenChat={openEmergencyChat} setPage={navigate} />}
        {page === 'deepfake' && <DeepfakeDetector />}
        {page === 'scanner' && <LinkScanner />}
        {page === 'spam' && <SpamChecker />}
        {page === 'app' && <AppChecker />}
        {page === 'rootcause' && <RootCause />}
        {page === 'complaints' && <ComplaintHub />}
        {page === 'awareness' && <Awareness />}
        {page === 'qrshield' && <QRShield />}
        {page === 'pro' && <VeyronPro />}
      </main>

      {showNavAndFooter && <Footer />}

      <CyberSaathi
        autoOpen={chatOpen}
        initialMode={chatEmergency ? 'emergency' : 'normal'}
        onOpenChange={(isOpen) => {
          if (!isOpen) {
            setChatOpen(false);
            setChatEmergency(false);
          }
        }}
      />
    </div>
  );
}

export default function App() {
  return (
    <LanguageProvider>
      <AppContent />
    </LanguageProvider>
  );
}
