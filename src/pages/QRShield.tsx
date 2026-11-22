import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  QrCode, Camera, Upload, ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle,
  Copy, ExternalLink, Wifi, Globe, UserCheck, FileText,
  RotateCcw, Loader2, Info, Lock, Unlock, Zap, ZapOff, LucideIcon
} from 'lucide-react';
import { useLang } from '../context/LanguageContext';
import { scanQR, scanQRPayload } from '../api';
import { recordUserActivity } from '../lib/userStats';

type Tab = 'camera' | 'upload' | 'text';
type RiskLabel = 'HIGH RISK' | 'SUSPICIOUS' | 'NO KNOWN THREAT DETECTED' | 'INSUFFICIENT EVIDENCE' | 'SCAN FAILED';
type PayloadType = 'url' | 'upi' | 'wifi' | 'contact' | 'text';

interface QrScanResult {
  payload_type: PayloadType;
  raw_payload?: string;
  verdict: string;
  risk_level?: RiskLabel;
  risk_score: number;
  action_url?: string;
  parsed_data: {
    payee_name?: string;
    payee_vpa?: string;
    amount?: number | string;
    transaction_note?: string;
    ssid?: string;
    security_type?: string;
    hostname?: string;
    overall_status?: string;
    name?: string;
    organization?: string;
    phone_numbers?: string[];
    [key: string]: unknown;
  };
  threat_indicators: string[];
  recommendations: string[];
  englishSummary?: string;
  hindiSummary?: string;
}

function normalizeRiskLabel(raw?: string): RiskLabel {
  const s = (raw || '').toUpperCase().trim();
  if (s.includes('HIGH') || s.includes('DANGER') || s.includes('MALICIOUS') || s.includes('BLOCKED')) return 'HIGH RISK';
  if (s.includes('SUSPICIOUS') || s.includes('RISKY')) return 'SUSPICIOUS';
  if (s.includes('FAIL')) return 'SCAN FAILED';
  if (s.includes('INSUFFICIENT')) return 'INSUFFICIENT EVIDENCE';
  if (s.includes('NO KNOWN') || s.includes('SAFE') || s.includes('CLEAN') || s.includes('TRUSTED') || s.includes('LOW')) return 'NO KNOWN THREAT DETECTED';
  return 'INSUFFICIENT EVIDENCE';
}

function mapQRVerdict(v?: string): 'safe' | 'suspicious' | 'dangerous' {
  const norm = normalizeRiskLabel(v);
  if (norm === 'NO KNOWN THREAT DETECTED') return 'safe';
  if (norm === 'HIGH RISK') return 'dangerous';
  return 'suspicious';
}

export default function QRShield() {
  const { t } = useLang();
  const [activeTab, setActiveTab] = useState<Tab>('upload');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QrScanResult | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  // Upload state
  const [dragOver, setDragOver] = useState(false);
  const [uploadedPreview, setUploadedPreview] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Manual text state
  const [manualText, setManualText] = useState('');

  // Camera state
  const videoRef = useRef<HTMLVideoElement>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [isStartingCamera, setIsStartingCamera] = useState(false);
  const [cameraStatus, setCameraStatus] = useState<'READY' | 'SCANNING' | 'ANALYZING'>('READY');
  const [facingMode, setFacingMode] = useState<'environment' | 'user'>('environment');
  const [videoDevices, setVideoDevices] = useState<MediaDeviceInfo[]>([]);
  const [currentDeviceIndex, setCurrentDeviceIndex] = useState(0);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [scanFeedback, setScanFeedback] = useState<string | null>(null);
  const [autoScanEnabled, setAutoScanEnabled] = useState(true);
  const [isCapturing, setIsCapturing] = useState(false);
  const streamRef = useRef<MediaStream | null>(null);
  const scanIntervalRef = useRef<number | null>(null);
  const isScanningFrameRef = useRef<boolean>(false);

  // Copy helper
  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2500);
  };

  // ─── Camera Management ───────────────────────────────────────────────────────

  const enumerateCameras = useCallback(async () => {
    try {
      if (navigator.mediaDevices?.enumerateDevices) {
        const devices = await navigator.mediaDevices.enumerateDevices();
        const videoInputs = devices.filter((d) => d.kind === 'videoinput');
        setVideoDevices(videoInputs);
      }
    } catch (e) {
      console.warn('[QRShield] Device enumeration error:', e);
    }
  }, []);

  const stopCamera = useCallback(() => {
    if (scanIntervalRef.current) {
      clearInterval(scanIntervalRef.current);
      scanIntervalRef.current = null;
    }
    isScanningFrameRef.current = false;
    setIsCapturing(false);
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setCameraActive(false);
    setCameraStatus('READY');
    setIsStartingCamera(false);
  }, []);

  const startCamera = useCallback(async (targetIndex?: number) => {
    stopCamera();
    setCameraError(null);
    setScanFeedback(null);
    setIsStartingCamera(true);

    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        throw new Error('Camera access is not supported by your browser.');
      }

      await enumerateCameras();

      const idx = targetIndex !== undefined ? targetIndex : currentDeviceIndex;
      const targetDevice = videoDevices[idx];

      const constraints: MediaStreamConstraints = {
        audio: false,
        video: targetDevice?.deviceId
          ? { deviceId: { exact: targetDevice.deviceId }, width: { ideal: 1280 }, height: { ideal: 720 } }
          : { facingMode, width: { ideal: 1280 }, height: { ideal: 720 } },
      };

      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      streamRef.current = stream;

      await enumerateCameras();

      const video = videoRef.current;
      if (!video) {
        throw new Error('Video preview element failed to initialize.');
      }

      video.srcObject = stream;

      try {
        await video.play();
      } catch (playErr) {
        console.warn('[QRShield] video.play() auto-play warning:', playErr);
      }

      setCameraActive(true);
      setCameraStatus('READY');
    } catch (err: unknown) {
      console.error('[QRShield] Camera start failed:', err);
      const isNotAllowed = err instanceof Error && err.name === 'NotAllowedError';
      const msg = err instanceof Error ? err.message : String(err);
      setCameraError(
        isNotAllowed
          ? 'Camera permission denied. Please allow camera access in your browser settings and try again.'
          : msg || 'Failed to start camera.'
      );
      stopCamera();
    } finally {
      setIsStartingCamera(false);
    }
  }, [currentDeviceIndex, enumerateCameras, facingMode, stopCamera, videoDevices]);

  const switchCamera = useCallback(() => {
    if (videoDevices.length > 1) {
      const nextIdx = (currentDeviceIndex + 1) % videoDevices.length;
      setCurrentDeviceIndex(nextIdx);
      startCamera(nextIdx);
    } else {
      const nextMode = facingMode === 'environment' ? 'user' : 'environment';
      setFacingMode(nextMode);
      stopCamera();
      setTimeout(() => {
        startCamera();
      }, 100);
    }
  }, [currentDeviceIndex, facingMode, startCamera, stopCamera, videoDevices.length]);

  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, [stopCamera]);

  // ─── Manual Payload Analysis Handler ───────────────────────────────────────

  const handleAnalyzePayload = useCallback(async (payloadToScan?: string) => {
    const text = (payloadToScan || manualText).trim();
    if (!text) return;
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const data = await scanQRPayload(text);
      setResult(data);
      recordUserActivity('qr', mapQRVerdict(data.verdict), data.englishSummary || data.verdict || 'QR payload analyzed');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || 'Failed to analyze QR payload.');
    } finally {
      setLoading(false);
    }
  }, [manualText]);

  // Scan single camera frame (used both by auto-loop and manual button)
  const scanCurrentFrame = useCallback(async (isManualTrigger: boolean = false) => {
    if (!videoRef.current || !cameraActive) return;
    const video = videoRef.current;
    if (video.videoWidth === 0 || video.videoHeight === 0 || video.readyState < 2) {
      if (isManualTrigger) {
        setScanFeedback('Camera feed is still initializing. Please wait a second and try again.');
      }
      return;
    }
    if (isScanningFrameRef.current) return;

    isScanningFrameRef.current = true;
    if (isManualTrigger) {
      setIsCapturing(true);
      setCameraStatus('ANALYZING');
      setScanFeedback(null);
    } else {
      setCameraStatus('SCANNING');
    }

    try {
      const canvas = document.createElement('canvas');
      const maxDim = 1280;
      const scale = Math.min(1, maxDim / Math.max(video.videoWidth, video.videoHeight));
      canvas.width = Math.round(video.videoWidth * scale);
      canvas.height = Math.round(video.videoHeight * scale);
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      // 1. Try native BarcodeDetector if available in browser (instant 0ms decoding)
      const customWin = window as unknown as {
        BarcodeDetector?: new (options?: { formats: string[] }) => {
          detect: (source: CanvasImageSource) => Promise<Array<{ rawValue?: string }>>;
        };
      };

      if (typeof customWin.BarcodeDetector !== 'undefined') {
        try {
          const detector = new customWin.BarcodeDetector({ formats: ['qr_code'] });
          const barcodes = await detector.detect(canvas);
          if (barcodes && barcodes.length > 0 && barcodes[0].rawValue) {
            stopCamera();
            await handleAnalyzePayload(barcodes[0].rawValue);
            return;
          }
        } catch {
          // Fallback to backend below
        }
      }

      // 2. Send frame to backend OpenCV decoder
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.90));
      if (!blob) return;

      try {
        const data = await scanQR(blob);
        if (data && data.raw_payload) {
          stopCamera();
          setResult(data);
          setScanFeedback(null);
          recordUserActivity('qr', mapQRVerdict(data.verdict), data.englishSummary || data.verdict || 'Camera QR code analyzed');
          return;
        }
      } catch {
        if (isManualTrigger) {
          setScanFeedback('No readable QR code was found. Move the code closer, improve lighting, and try again.');
        }
      }
    } finally {
      isScanningFrameRef.current = false;
      if (isManualTrigger) setIsCapturing(false);
      setCameraStatus('READY');
    }
  }, [cameraActive, stopCamera, handleAnalyzePayload]);

  // Automated continuous scanning interval loop when camera is active and autoScanEnabled
  useEffect(() => {
    if (cameraActive && autoScanEnabled && !isCapturing && !loading && !result) {
      scanIntervalRef.current = window.setInterval(() => {
        scanCurrentFrame(false);
      }, 900);
    } else {
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
      }
    }
    return () => {
      if (scanIntervalRef.current) {
        clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
      }
    };
  }, [cameraActive, autoScanEnabled, isCapturing, loading, result, scanCurrentFrame]);

  // Manual capture trigger button handler
  const captureCameraFrame = useCallback(() => {
    scanCurrentFrame(true);
  }, [scanCurrentFrame]);

  // ─── File Upload Handler ───────────────────────────────────────────────────

  const handleFileUpload = async (file: File) => {
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      setError(t('File size exceeds 10MB limit. Please upload a smaller image file.', 'फ़ाइल 10MB सीमा से अधिक है। कृपया छोटी छवि अपलोड करें।'));
      return;
    }
    setError(null);
    setResult(null);

    // Show image preview
    const reader = new FileReader();
    reader.onload = () => setUploadedPreview(reader.result as string);
    reader.readAsDataURL(file);

    setLoading(true);
    try {
      const data = await scanQR(file);
      setResult(data);
      recordUserActivity('qr', mapQRVerdict(data.verdict), data.englishSummary || data.verdict || 'Uploaded QR code analyzed');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || 'Failed to decode QR code. Please ensure the QR code image is clear and well-lit.');
    } finally {
      setLoading(false);
    }
  };

  // ─── Demo Samples ─────────────────────────────────────────────────────────

  const loadSample = (sampleText: string) => {
    setManualText(sampleText);
    handleAnalyzePayload(sampleText);
  };

  // ─── Verdict Configuration ─────────────────────────────────────────────────

  const verdictStyles: Record<RiskLabel, {
    bg: string;
    badge: string;
    icon: LucideIcon;
    title: string;
    meterBg: string;
  }> = {
    'HIGH RISK': {
      bg: 'bg-red-500/10 border-red-500/30 text-red-400',
      badge: 'bg-red-500/20 text-red-300 border-red-500/40',
      icon: ShieldAlert,
      title: t('HIGH RISK', 'उच्च जोखिम - खतरा संभावित'),
      meterBg: 'bg-red-500',
    },
    'SUSPICIOUS': {
      bg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
      badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      icon: AlertTriangle,
      title: t('SUSPICIOUS', 'संदिग्ध - सावधानी बरतें'),
      meterBg: 'bg-amber-500',
    },
    'NO KNOWN THREAT DETECTED': {
      bg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
      badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      icon: CheckCircle,
      title: t('NO KNOWN THREAT DETECTED', 'कोई ज्ञात खतरा नहीं मिला'),
      meterBg: 'bg-emerald-500',
    },
    'INSUFFICIENT EVIDENCE': {
      bg: 'bg-slate-500/10 border-slate-500/30 text-slate-300',
      badge: 'bg-slate-500/20 text-slate-300 border-slate-500/40',
      icon: Info,
      title: t('INSUFFICIENT EVIDENCE', 'अपर्याप्त साक्ष्य - असत्यापित'),
      meterBg: 'bg-slate-500',
    },
    'SCAN FAILED': {
      bg: 'bg-rose-500/10 border-rose-500/30 text-rose-400',
      badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      icon: AlertTriangle,
      title: t('SCAN FAILED', 'स्कैन असफल'),
      meterBg: 'bg-rose-500',
    },
  };

  const currentLabel = normalizeRiskLabel(result?.risk_level || result?.verdict);
  const vConfig = result ? verdictStyles[currentLabel] : verdictStyles['NO KNOWN THREAT DETECTED'];

  return (
    <div className="min-h-screen bg-[#060d1f] pt-16 pb-24 text-white">
      <div className="max-w-4xl mx-auto px-4 sm:px-6">

        {/* ─── Header ─── */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/5">
              <QrCode className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-['Space_Grotesk'] text-3xl font-bold tracking-tight text-white">
                  {t('Veyron QR Shield', 'वेरॉन क्यूआर शील्ड')}
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  Zero-Trust
                </span>
              </div>
              <p className="text-slate-400 text-sm mt-0.5">
                {t(
                  'Zero-Trust QR Code Scanner & Fraud Prevention Engine. Inspect URLs, UPI Payments, Wi-Fi networks, and contact payloads safely before opening or paying.',
                  'ज़ीरो-ट्रस्ट क्यूआर कोड स्कैनर। भुगतान करने या लिंक खोलने से पहले यूआरएल, यूपीआई और वाई-फाई पेलोड की सुरक्षा जांचें।'
                )}
              </p>
            </div>
          </div>
        </div>

        {/* ─── Input Method Selector ─── */}
        <div className="flex p-1 bg-white/5 border border-slate-800 rounded-xl mb-6">
          <button
            onClick={() => { setActiveTab('upload'); stopCamera(); setResult(null); setError(null); }}
            className={`flex-1 flex items-center justify-center gap-2 py-2.5 text-sm font-medium rounded-lg transition-all ${
              activeTab === 'upload'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-4 h-4" />
            {t('Upload Image', 'छवि अपलोड करें')}
          </button>
          <button
            onClick={() => { setActiveTab('camera'); setResult(null); setError(null); }}
            className={`flex-1 flex items-center justify-center gap-2 py-2.5 text-sm font-medium rounded-lg transition-all ${
              activeTab === 'camera'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Camera className="w-4 h-4" />
            {t('Camera Scanner', 'कैमरा स्कैनर')}
          </button>
          <button
            onClick={() => { setActiveTab('text'); stopCamera(); setResult(null); setError(null); }}
            className={`flex-1 flex items-center justify-center gap-2 py-2.5 text-sm font-medium rounded-lg transition-all ${
              activeTab === 'text'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            {t('Payload Inspector', 'पेलोड विश्लेषक')}
          </button>
        </div>

        {/* ─── Main Input Panels ─── */}
        <AnimatePresence mode="wait">
          {activeTab === 'upload' && (
            <motion.div
              key="upload"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 mb-8 text-center"
            >
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  if (e.dataTransfer.files?.[0]) handleFileUpload(e.dataTransfer.files[0]);
                }}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 cursor-pointer transition-all ${
                  dragOver
                    ? 'border-cyan-400 bg-cyan-500/10'
                    : 'border-slate-700 hover:border-slate-500 bg-slate-900/40'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp,image/jpg"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files?.[0]) handleFileUpload(e.target.files[0]);
                  }}
                />

                {uploadedPreview ? (
                  <div className="flex flex-col items-center">
                    <img
                      src={uploadedPreview}
                      alt="Uploaded QR Code"
                      className="max-h-48 rounded-lg border border-slate-700 shadow-md mb-4 object-contain"
                    />
                    <p className="text-xs text-slate-400">{t('Click or drag another image to replace', 'बदलने के लिए दूसरी छवि चुनें')}</p>
                  </div>
                ) : (
                  <div className="flex flex-col items-center">
                    <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4">
                      <QrCode className="w-8 h-8" />
                    </div>
                    <h3 className="font-semibold text-lg text-white mb-1">
                      {t('Drop your QR code image here', 'क्यूआर कोड छवि यहाँ खींचें')}
                    </h3>
                    <p className="text-slate-400 text-sm mb-4">
                      {t('Supports PNG, JPG, JPEG, and WebP format', 'PNG, JPG, JPEG, और WebP प्रारूप समर्थित')}
                    </p>
                    <span className="px-4 py-2 bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 rounded-lg text-sm font-medium hover:bg-cyan-500/30 transition-all">
                      {t('Browse Files', 'फ़ाइल चुनें')}
                    </span>
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {activeTab === 'camera' && (
            <motion.div
              key="camera"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 mb-8 text-center"
            >
              {cameraError ? (
                <div className="p-6 bg-red-500/10 border border-red-500/30 rounded-xl text-red-300 text-sm max-w-md mx-auto">
                  <ShieldAlert className="w-8 h-8 text-red-400 mx-auto mb-2" />
                  <p className="font-semibold">{t('Camera Error', 'कैमरा त्रुटि')}</p>
                  <p className="mt-1">{cameraError}</p>
                  <button
                    type="button"
                    onClick={() => startCamera()}
                    className="mt-4 px-4 py-2 bg-red-500/20 border border-red-500/40 rounded-lg text-xs font-semibold text-red-200 hover:bg-red-500/30"
                  >
                    {t('Retry Camera Access', 'कैमरा पुनः प्रारंभ करें')}
                  </button>
                </div>
              ) : (
                <div className="relative max-w-md mx-auto">
                  {/* Real-time Scanner Status Pill & Auto-Scan Toggle */}
                  {cameraActive && (
                    <div className="flex items-center justify-between px-2 mb-3">
                      <div className="flex items-center gap-2">
                        <span className="flex h-2.5 w-2.5 relative">
                          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${
                            isCapturing || cameraStatus === 'ANALYZING'
                              ? 'bg-amber-400 opacity-75'
                              : cameraStatus === 'SCANNING'
                              ? 'bg-blue-400 opacity-75'
                              : autoScanEnabled
                              ? 'bg-emerald-400 opacity-75'
                              : 'bg-cyan-400 opacity-75'
                          }`}></span>
                          <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                            isCapturing || cameraStatus === 'ANALYZING'
                              ? 'bg-amber-500'
                              : cameraStatus === 'SCANNING'
                              ? 'bg-blue-500'
                              : autoScanEnabled
                              ? 'bg-emerald-500'
                              : 'bg-cyan-500'
                          }`}></span>
                        </span>
                        <span className={`text-xs font-semibold ${
                          isCapturing || cameraStatus === 'ANALYZING'
                            ? 'text-amber-300'
                            : cameraStatus === 'SCANNING'
                            ? 'text-blue-300'
                            : autoScanEnabled
                            ? 'text-emerald-300'
                            : 'text-cyan-300'
                        }`}>
                          {isCapturing || cameraStatus === 'ANALYZING'
                            ? t('Analyzing Captured Frame...', 'फ़्रेम का विश्लेषण हो रहा है...')
                            : cameraStatus === 'SCANNING'
                            ? t('Scanning QR Code...', 'क्यूआर कोड स्कैन हो रहा है...')
                            : autoScanEnabled
                            ? t('Auto-Scan Active • Align QR in Frame', 'स्वचालित स्कैनर सक्रिय • फ़्रेम में संरेखित करें')
                            : t('Camera Ready • Tap Capture & Scan', 'कैमरा तैयार • कैप्चर और स्कैन दबाएँ')}
                        </span>
                      </div>

                      {/* Auto-Scan Toggle Pill */}
                      <button
                        type="button"
                        onClick={() => setAutoScanEnabled((prev) => !prev)}
                        className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold border flex items-center gap-1.5 transition-all ${
                          autoScanEnabled
                            ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/25'
                            : 'bg-slate-800/80 border-slate-700 text-slate-400 hover:text-slate-200'
                        }`}
                        title={autoScanEnabled ? 'Auto-Scan is ON: Automatically analyzing incoming frames' : 'Auto-Scan is OFF: Manual capture only'}
                      >
                        {autoScanEnabled ? <Zap className="w-3 h-3 text-emerald-400" /> : <ZapOff className="w-3 h-3 text-slate-400" />}
                        <span>{autoScanEnabled ? 'Auto-Scan: ON' : 'Auto-Scan: OFF'}</span>
                      </button>
                    </div>
                  )}

                  {/* Persistent Video Viewfinder Container (ALWAYS mounted so videoRef is ready) */}
                  <div className={`relative rounded-2xl overflow-hidden border-2 border-cyan-500/50 bg-black shadow-2xl ${cameraActive ? 'block' : 'hidden'}`}>
                    <video
                      ref={videoRef}
                      autoPlay
                      playsInline
                      muted
                      className="w-full h-80 object-cover"
                    />

                    {/* Viewfinder Overlay with Animated Scan Line */}
                    <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
                      <div className="w-56 h-56 border-2 border-cyan-400/80 rounded-2xl relative shadow-[0_0_20px_rgba(6,182,212,0.3)]">
                        <div className="absolute -top-1 -left-1 w-6 h-6 border-t-4 border-l-4 border-cyan-400 rounded-tl-lg" />
                        <div className="absolute -top-1 -right-1 w-6 h-6 border-t-4 border-r-4 border-cyan-400 rounded-tr-lg" />
                        <div className="absolute -bottom-1 -left-1 w-6 h-6 border-b-4 border-l-4 border-cyan-400 rounded-bl-lg" />
                        <div className="absolute -bottom-1 -right-1 w-6 h-6 border-b-4 border-r-4 border-cyan-400 rounded-br-lg" />

                        {/* Animated Laser Bar */}
                        <div className="w-full h-0.5 bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-pulse absolute top-1/2 -translate-y-1/2 shadow-[0_0_12px_#22d3ee]" />
                      </div>
                    </div>
                  </div>

                  {cameraActive ? (
                    <>
                      {/* Scan Failure / Instructions Feedback Banner */}
                      {scanFeedback && (
                        <div className="mt-3 p-3 bg-amber-500/15 border border-amber-500/35 rounded-xl text-amber-200 text-xs flex items-center justify-between gap-2 text-left">
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                            <span>{scanFeedback}</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => setScanFeedback(null)}
                            className="text-amber-400 hover:text-white text-xs px-1"
                          >
                            ✕
                          </button>
                        </div>
                      )}

                      {/* Camera Controls Bar */}
                      <div className="flex items-center justify-center gap-2.5 mt-3">
                        <button
                          type="button"
                          onClick={captureCameraFrame}
                          disabled={isCapturing || loading}
                          className="flex-1 py-3 px-4 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-60 text-slate-950 font-bold rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all text-sm"
                        >
                          {isCapturing || loading ? (
                            <>
                              <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                              <span>{t('Analyzing Frame...', 'विश्लेषण हो रहा है...')}</span>
                            </>
                          ) : (
                            <>
                              <QrCode className="w-4 h-4 text-slate-950" />
                              <span>{t('Capture & Scan QR', 'कैप्चर और स्कैन करें')}</span>
                            </>
                          )}
                        </button>

                        <button
                          type="button"
                          onClick={switchCamera}
                          className="p-3 bg-white/10 hover:bg-white/20 border border-slate-700 rounded-xl text-slate-300 transition-all"
                          title={videoDevices.length > 1 ? `Switch camera (${currentDeviceIndex + 1}/${videoDevices.length})` : 'Flip front/back camera'}
                        >
                          <RotateCcw className="w-4 h-4" />
                        </button>

                        <button
                          type="button"
                          onClick={stopCamera}
                          className="py-3 px-3.5 bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 text-xs font-semibold rounded-xl transition-all"
                        >
                          {t('Stop', 'बंद करें')}
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="py-12 flex flex-col items-center">
                      <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4">
                        <Camera className="w-8 h-8" />
                      </div>
                      <h3 className="font-semibold text-lg text-white mb-2">
                        {t('Live Camera QR Scanner', 'लाइव कैमरा क्यूआर स्कैनर')}
                      </h3>
                      <p className="text-slate-400 text-sm max-w-sm mb-6">
                        {t(
                          'Scan physical QR codes from paper, bills, or payment counters safely in real-time.',
                          'कागज़, बिल या काउंटर पर लगे क्यूआर कोड को तुरंत और सुरक्षित स्कैन करें।'
                        )}
                      </p>
                      <button
                        type="button"
                        onClick={() => startCamera()}
                        disabled={isStartingCamera}
                        className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-70 text-slate-950 font-semibold rounded-xl flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
                      >
                        {isStartingCamera ? (
                          <>
                            <Loader2 className="w-5 h-5 animate-spin text-slate-950" />
                            <span>{t('Starting Camera...', 'कैमरा प्रारंभ हो रहा है...')}</span>
                          </>
                        ) : (
                          <>
                            <Camera className="w-5 h-5" />
                            <span>{t('Open Camera Viewfinder', 'कैमरा प्रारंभ करें')}</span>
                          </>
                        )}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}

          {activeTab === 'text' && (
            <motion.div
              key="text"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6 mb-8"
            >
              <label className="block text-sm font-medium text-slate-300 mb-2">
                {t('Raw QR Payload Text', 'कच्चा क्यूआर पेलोड टेक्स्ट')}
              </label>
              <textarea
                value={manualText}
                onChange={(e) => setManualText(e.target.value)}
                placeholder={t(
                  'Paste raw payload (e.g. upi://pay?pa=... or https://... or WIFI:T:WPA;S:...)',
                  'कच्चा पेलोड यहाँ चिपकाएँ (उदा. upi://pay?... या https://... या WIFI:...)'
                )}
                rows={3}
                className="w-full bg-slate-900/60 border border-slate-700 rounded-xl p-3 text-sm text-white focus:outline-none focus:border-cyan-400 font-mono resize-none mb-4"
              />

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                  <span>{t('Quick Test Demos:', 'त्वरित डेमो परीक्षण:')}</span>
                  <button
                    onClick={() => loadSample('upi://pay?pa=electricity-bill-refund@okhdfcbank&pn=Electricity%20Refund%20Officer&am=45000&cu=INR')}
                    className="px-2.5 py-1 bg-red-500/10 border border-red-500/30 rounded text-red-300 hover:bg-red-500/20"
                  >
                    UPI Fraud
                  </button>
                  <button
                    onClick={() => loadSample('WIFI:T:nopass;S:Airport_Free_WiFi;P:;;')}
                    className="px-2.5 py-1 bg-amber-500/10 border border-amber-500/30 rounded text-amber-300 hover:bg-amber-500/20"
                  >
                    Open Wi-Fi
                  </button>
                  <button
                    onClick={() => loadSample('https://google.com')}
                    className="px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/30 rounded text-emerald-300 hover:bg-emerald-500/20"
                  >
                    Safe URL
                  </button>
                </div>

                <button
                  onClick={() => handleAnalyzePayload()}
                  disabled={loading || !manualText.trim()}
                  className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold rounded-xl text-sm flex items-center gap-2 shadow-md shadow-cyan-500/20 transition-all ml-auto"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  {t('Analyze Payload', 'पेलोड का विश्लेषण करें')}
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ─── Loading Overlay ─── */}
        {loading && (
          <div className="py-12 flex flex-col items-center justify-center">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin mb-3" />
            <p className="text-sm font-medium text-slate-300">{t('Executing Deep Zero-Trust Security Scan...', 'गहन सुरक्षा विश्लेषण चल रहा है...')}</p>
          </div>
        )}

        {/* ─── Error Notification ─── */}
        {error && !loading && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl mb-6 text-red-300 text-sm flex items-start gap-3"
          >
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">{t('Scan Alert', 'स्कैन चेतावनी')}</p>
              <p className="mt-0.5 text-xs text-red-200">{error}</p>
            </div>
          </motion.div>
        )}

        {/* ─── Security Report Dashboard ─── */}
        {result && !loading && (
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            className="space-y-6"
          >
            {/* Verdict Header Banner */}
            <div className={`p-6 rounded-2xl border ${vConfig.bg} shadow-xl backdrop-blur-xl`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-xl bg-white/10 flex items-center justify-center">
                    <vConfig.icon className="w-7 h-7" />
                  </div>
                  <div>
                    <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold tracking-wide uppercase border mb-1 ${vConfig.badge}`}>
                      {(result.payload_type || 'generic').toUpperCase()} PAYLOAD
                    </span>
                    <h2 className="text-xl font-bold tracking-tight">{vConfig.title}</h2>
                  </div>
                </div>

                <div className="text-right sm:border-l sm:border-white/10 sm:pl-6">
                  <div className="text-xs uppercase tracking-wider text-slate-400 font-medium mb-1">
                    {t('Fraud Risk Score', 'धोखाधड़ी जोखिम स्कोर')}
                  </div>
                  <div className="text-3xl font-extrabold font-mono tracking-tight">
                    {result.risk_score}<span className="text-base text-slate-500 font-normal">/100</span>
                  </div>
                </div>
              </div>

              {/* Visual Risk Gauge Meter */}
              <div className="w-full bg-slate-900/60 rounded-full h-2 mt-5 overflow-hidden">
                <div
                  className={`h-full ${vConfig.meterBg} transition-all duration-700`}
                  style={{ width: `${Math.max(4, result.risk_score)}%` }}
                />
              </div>
            </div>

            {/* Structured Payload Breakdown Card */}
            <div className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                {t('Decoded Payload Intelligence', 'डिकोड की गई पेलोड जानकारी')}
              </h3>

              {/* UPI Specific Details */}
              {result.payload_type === 'upi' && (
                <div className="space-y-4">
                  {/* Critical UPI Rule Alert */}
                  <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-start gap-3">
                    <ShieldAlert className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="font-bold text-sm text-amber-200">
                        {t('UNIVERSAL UPI SAFETY ADVISORY', 'सार्वभौमिक यूपीआई सुरक्षा सलाह')}
                      </p>
                      <p className="mt-1">
                        {t(
                          'Scanning a QR code is ONLY used to DEDUCT money from your account. You NEVER need to scan a QR code or enter your UPI PIN to receive money, lottery rewards, or refunds.',
                          'क्यूआर कोड स्कैन करने का उपयोग केवल खाते से पैसे काटने के लिए होता है। पैसे या रिफंड प्राप्त करने के लिए कभी भी पिन दर्ज करने या क्यूआर स्कैन करने की आवश्यकता नहीं होती।'
                        )}
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Payee Name', 'प्राप्तकर्ता का नाम')}</span>
                      <span className="font-semibold text-white">{result.parsed_data?.payee_name || t('Not specified', 'निर्दिष्ट नहीं')}</span>
                    </div>
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Payee UPI ID (VPA)', 'प्राप्तकर्ता यूपीआई आईडी')}</span>
                      <span className="font-mono text-cyan-300">{result.parsed_data?.payee_vpa || 'N/A'}</span>
                    </div>
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Requested Amount', 'अनुरोधित राशि')}</span>
                      <span className="font-bold text-lg text-emerald-400">
                        {result.parsed_data?.amount ? `₹${result.parsed_data.amount.toLocaleString('en-IN')}` : t('User Entered (Custom)', 'कस्टम (उपयोगकर्ता द्वारा)')}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Transaction Note', 'लेनदेन नोट')}</span>
                      <span className="text-slate-300">{result.parsed_data?.transaction_note || t('None provided', 'कोई नहीं')}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Wi-Fi Specific Details */}
              {result.payload_type === 'wifi' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Network SSID Name', 'नेटवर्क नाम (SSID)')}</span>
                      <span className="font-semibold text-white flex items-center gap-2">
                        <Wifi className="w-4 h-4 text-cyan-400" />
                        {result.parsed_data?.ssid || 'Hidden Network'}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Security Encryption', 'सुरक्षा एन्क्रिप्शन')}</span>
                      <span className={`font-semibold flex items-center gap-1.5 ${result.parsed_data?.security_type === 'NOPASS' ? 'text-red-400' : 'text-emerald-400'}`}>
                        {result.parsed_data?.security_type === 'NOPASS' ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                        {result.parsed_data?.security_type || 'Unknown'}
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* URL Specific Details */}
              {result.payload_type === 'url' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Target Hostname', 'होस्टनेम')}</span>
                      <span className="font-semibold text-white flex items-center gap-2">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        {result.parsed_data?.hostname || 'Analyzed Host'}
                      </span>
                    </div>
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Reputation Status', 'प्रतिष्ठा स्थिति')}</span>
                      <span className="font-semibold text-cyan-300">{result.parsed_data?.overall_status || 'Analyzed'}</span>
                    </div>
                  </div>
                  <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                    <span className="text-xs text-slate-500 block mb-1">{t('Destination URL', 'गंतव्य लिंक')}</span>
                    <span className="font-mono text-xs text-slate-300 break-all">{result.action_url || result.raw_payload}</span>
                  </div>
                </div>
              )}

              {/* Contact Card Details */}
              {result.payload_type === 'contact' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                  <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                    <span className="text-xs text-slate-500 block">{t('Contact Name', 'नाम')}</span>
                    <span className="font-semibold text-white flex items-center gap-2">
                      <UserCheck className="w-4 h-4 text-cyan-400" />
                      {result.parsed_data?.name || 'Contact'}
                    </span>
                  </div>
                  {result.parsed_data?.organization && (
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Organization', 'संगठन')}</span>
                      <span className="text-slate-300">{result.parsed_data.organization}</span>
                    </div>
                  )}
                  {result.parsed_data?.phone_numbers && result.parsed_data.phone_numbers.length > 0 && (
                    <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-800">
                      <span className="text-xs text-slate-500 block">{t('Phone Numbers', 'फ़ोन नंबर')}</span>
                      <span className="font-mono text-cyan-300">{result.parsed_data.phone_numbers.join(', ')}</span>
                    </div>
                  )}
                </div>
              )}

              {/* Plain Text Details */}
              {result.payload_type === 'text' && (
                <div className="p-4 bg-slate-900/50 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 break-all">
                  {result.raw_payload}
                </div>
              )}
            </div>

            {/* Threat Indicators & Forensic Findings */}
            {result.threat_indicators?.length > 0 && (
              <div className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  {t('Threat Indicators Detected', 'पहचाने गए खतरे के संकेत')}
                </h3>
                <ul className="space-y-2">
                  {result.threat_indicators.map((ind, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-xs text-slate-300 bg-red-500/5 border border-red-500/20 rounded-lg p-2.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 flex-shrink-0" />
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Actionable Recommendations */}
            {result.recommendations?.length > 0 && (
              <div className="bg-white/5 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6">
                <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  {t('Security Recommendations', 'सुरक्षा सिफारिशें')}
                </h3>
                <ul className="space-y-2.5">
                  {result.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-xs text-slate-300">
                      <span className="w-5 h-5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center justify-center font-bold text-[10px] flex-shrink-0">
                        {i + 1}
                      </span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Zero-Trust Action Bar (NO AUTO-NAVIGATION) */}
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-2xl flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => copyToClipboard(result.action_url || result.raw_payload || '', 'payload')}
                  className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-slate-700 rounded-xl text-xs font-semibold text-slate-200 flex items-center gap-2 transition-all"
                >
                  <Copy className="w-3.5 h-3.5 text-cyan-400" />
                  {copied === 'payload' ? t('Copied!', 'कॉपी किया!') : t('Copy Payload', 'पेलोड कॉपी करें')}
                </button>

                {result.payload_type === 'url' && result.action_url && (
                  <button
                    onClick={() => {
                      const target = result.action_url || '';
                      try {
                        const parsed = new URL(target);
                        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                          alert(`Security Alert: Blocked non-web URI scheme (${parsed.protocol}). Only standard http:// and https:// URLs can be opened.`);
                          return;
                        }
                      } catch {
                        alert('Security Alert: Malformed URL format. Navigation aborted.');
                        return;
                      }

                      if (currentLabel === 'HIGH RISK' || currentLabel === 'SUSPICIOUS') {
                        const conf = window.confirm(
                          `SECURITY WARNING: This URL is rated as ${currentLabel}. Opening external untrusted destinations may compromise your device or personal data.\n\nDestination: ${target}\n\nDo you explicitly wish to proceed?`
                        );
                        if (!conf) return;
                      }
                      window.open(target, '_blank', 'noopener,noreferrer');
                    }}
                    className={`px-4 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition-all ${
                      currentLabel === 'HIGH RISK'
                        ? 'bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30'
                        : currentLabel === 'SUSPICIOUS'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 hover:bg-amber-500/30'
                        : 'bg-cyan-500 text-slate-950 font-bold hover:bg-cyan-400'
                    }`}
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                    {t('Open Destination (External Tab)', 'गंतव्य खोलें (बाहरी टैब)')}
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 ml-auto">
                <button
                  type="button"
                  onClick={() => {
                    setResult(null);
                    setScanFeedback(null);
                    setError(null);
                    setActiveTab('camera');
                    setTimeout(() => startCamera(), 120);
                  }}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl text-xs flex items-center gap-2 transition-all shadow-md shadow-cyan-500/20"
                >
                  <Camera className="w-3.5 h-3.5" />
                  {t('Scan Again with Camera', 'कैमरे से पुनः स्कैन करें')}
                </button>
                <button
                  type="button"
                  onClick={() => { setResult(null); setUploadedPreview(null); setManualText(''); setScanFeedback(null); }}
                  className="px-4 py-2 bg-white/5 hover:bg-white/10 border border-slate-800 rounded-xl text-xs text-slate-400 hover:text-slate-200 flex items-center gap-2 transition-all"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  {t('Reset Scanner', 'रीसेट करें')}
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
