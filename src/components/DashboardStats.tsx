import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Activity, AlertTriangle, CheckCircle, ShieldAlert, Target } from 'lucide-react';
import { getUserActivity, UserActivity } from '../lib/userStats';
import { useLang } from '../context/LanguageContext';
import { GlassmorphicPanel } from './premium/PremiumUI';

export default function DashboardStats() {
  const { t } = useLang();
  const [stats, setStats] = useState({
    safetyScore: 100,
    completedChecks: 0,
    suspiciousChecks: 0,
    dangerousChecks: 0,
    recent: [] as UserActivity[]
  });

  useEffect(() => {
    setStats(getUserActivity());
    
    // Listen for custom event to refresh stats if needed
    const handleRefresh = () => setStats(getUserActivity());
    window.addEventListener('veyron-activity-updated', handleRefresh);
    return () => window.removeEventListener('veyron-activity-updated', handleRefresh);
  }, []);

  if (stats.completedChecks === 0) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mt-16 text-center"
      >
        <p className="text-slate-500 font-mono text-sm">
          {t('No recent scan activity. Run a scan to build your threat profile.', 'कोई हालिया स्कैन गतिविधि नहीं। अपनी खतरे की प्रोफ़ाइल बनाने के लिए एक स्कैन चलाएं।')}
        </p>
      </motion.div>
    );
  }

  const scoreColor = 
    stats.safetyScore >= 90 ? 'text-green-400' :
    stats.safetyScore >= 70 ? 'text-yellow-400' : 'text-red-400';
    
  const scoreRingColor = 
    stats.safetyScore >= 90 ? 'stroke-green-400' :
    stats.safetyScore >= 70 ? 'stroke-yellow-400' : 'stroke-red-400';

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4, duration: 0.6 }}
      className="mt-16 grid lg:grid-cols-3 gap-6"
    >
      {/* Safety Score Card */}
      <GlassmorphicPanel hover={false} className="relative overflow-hidden lg:col-span-1 flex flex-col justify-center">
        <div className="absolute top-0 right-0 p-4 opacity-10">
          <Target className="w-24 h-24" />
        </div>
        <h3 className="text-slate-400 font-semibold text-sm tracking-wider uppercase mb-6">
          {t('Your Safety Score', 'आपका सुरक्षा स्कोर')}
        </h3>
        
        <div className="flex items-center gap-6 relative z-10">
          <div className="relative w-24 h-24 flex-shrink-0">
            <svg viewBox="0 0 36 36" className="w-full h-full transform -rotate-90">
              <path
                className="stroke-slate-800"
                strokeWidth="3"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className={`${scoreRingColor} transition-all duration-1000 ease-out`}
                strokeWidth="3"
                strokeDasharray={`${stats.safetyScore}, 100`}
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-2xl font-bold font-mono ${scoreColor}`}>
                {stats.safetyScore}
              </span>
            </div>
          </div>
          
          <div>
            <p className="text-sm text-slate-300 mb-1">
              {stats.safetyScore >= 90 ? t('System secure', 'सिस्टम सुरक्षित है') :
               stats.safetyScore >= 70 ? t('Elevated risk', 'उच्च जोखिम') : t('Critical threats detected', 'गंभीर खतरे पाए गए')}
            </p>
            <p className="text-xs text-slate-500 font-mono">
              {stats.completedChecks} {t('scans completed', 'स्कैन पूरे हुए')}
            </p>
          </div>
        </div>
      </GlassmorphicPanel>

      {/* Threat Distribution */}
      <GlassmorphicPanel hover={false} className="lg:col-span-2">
        <div className="flex items-center gap-2 mb-6">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="text-slate-400 font-semibold text-sm tracking-wider uppercase">
            {t('Recent Threat Activity', 'हाल की गतिविधि')}
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          {/* Metrics */}
          <div className="flex gap-4">
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 flex-1">
              <ShieldAlert className="w-5 h-5 text-red-400 mb-2" />
              <p className="text-2xl font-mono font-bold text-red-400">{stats.dangerousChecks}</p>
              <p className="text-xs text-slate-500 uppercase tracking-wider">{t('Critical', 'गंभीर')}</p>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 flex-1">
              <AlertTriangle className="w-5 h-5 text-yellow-400 mb-2" />
              <p className="text-2xl font-mono font-bold text-yellow-400">{stats.suspiciousChecks}</p>
              <p className="text-xs text-slate-500 uppercase tracking-wider">{t('Suspicious', 'संदिग्ध')}</p>
            </div>
            <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4 flex-1">
              <CheckCircle className="w-5 h-5 text-green-400 mb-2" />
              <p className="text-2xl font-mono font-bold text-green-400">
                {stats.completedChecks - stats.dangerousChecks - stats.suspiciousChecks}
              </p>
              <p className="text-xs text-slate-500 uppercase tracking-wider">{t('Safe', 'सुरक्षित')}</p>
            </div>
          </div>

          {/* Recent List */}
          <div className="space-y-2">
            {stats.recent.slice(0, 3).map((activity) => (
              <div key={activity.id} className="flex items-center gap-3 bg-slate-800/50 rounded-lg p-2.5 border border-slate-700/50">
                <div className={`w-2 h-2 rounded-full ${
                  activity.verdict === 'dangerous' ? 'bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.8)]' :
                  activity.verdict === 'suspicious' ? 'bg-yellow-400 shadow-[0_0_8px_rgba(250,204,21,0.8)]' :
                  'bg-green-400'
                }`} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-slate-300 truncate">{activity.summary}</p>
                  <p className="text-[10px] text-slate-500 font-mono">
                    {new Date(activity.timestamp).toLocaleTimeString()} • {activity.tool.toUpperCase()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </GlassmorphicPanel>
    </motion.div>
  );
}
