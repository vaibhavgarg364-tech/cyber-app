/**
 * useSpeechEngine — Production-grade voice controller for CyberSaathi.
 *
 * Architecture:
 * 1. Single-Use Disposable Instances: SpeechRecognition is created FRESH on every tap.
 * 2. Voice Typing UX: Appends live to existing textbox instead of overwriting.
 * 3. NO Auto-Send: The microphone only populates the input. The user manually sends.
 * 4. GC Bug Fix: TTS utterance stored in a ref prevents Chrome from aborting long speech.
 * 5. Sentence Chunking: Long responses are split into natural sentences for smoother TTS.
 * 6. Markdown Cleaning: All markdown artifacts stripped before speech for natural output.
 */

import { useState, useRef, useEffect, useCallback } from 'react';

export interface SpeechEngineOptions {
  /** 'en-IN' | 'hi-IN' */
  lang: string;
}

export interface SpeechEngine {
  isListening: boolean;
  voiceSupported: boolean;
  transcript: string;
  setTranscript: (val: string) => void;
  startListening: () => void;
  stopListening: () => void;
  toggleListening: () => void;
  clearTranscript: () => void;

  isSpeaking: boolean;
  ttsEnabled: boolean;
  setTtsEnabled: (val: boolean) => void;
  ttsSupported: boolean;
  speakText: (text: string) => void;
  stopSpeaking: () => void;
  activeVoiceName: string;
  previewVoice: () => void;

  voiceError: string;
  clearVoiceError: () => void;
}

// ── Minimal Web Speech API typings (not in lib.dom for all TS versions) ──

interface SpeechRecognitionAlternativeLike {
  transcript: string;
}

interface SpeechRecognitionResultLike extends ArrayLike<SpeechRecognitionAlternativeLike> {
  isFinal?: boolean;
}

interface SpeechRecognitionResultEventLike {
  results: ArrayLike<SpeechRecognitionResultLike>;
}

interface SpeechRecognitionErrorEventLike {
  error: string;
}

interface SpeechRecognitionLike {
  continuous: boolean;
  interimResults: boolean;
  maxAlternatives: number;
  lang: string;
  start: () => void;
  stop: () => void;
  abort: () => void;
  onstart: (() => void) | null;
  onaudiostart: (() => void) | null;
  onsoundstart: (() => void) | null;
  onspeechstart: (() => void) | null;
  onspeechend: (() => void) | null;
  onsoundend: (() => void) | null;
  onaudioend: (() => void) | null;
  onresult: ((event: SpeechRecognitionResultEventLike) => void) | null;
  onerror: ((event: SpeechRecognitionErrorEventLike) => void) | null;
  onend: (() => void) | null;
}

type SpeechRecognitionCtor = new () => SpeechRecognitionLike;

function getSpeechRecognitionCtor(): SpeechRecognitionCtor | undefined {
  if (typeof window === 'undefined') return undefined;
  const w = window as unknown as {
    SpeechRecognition?: SpeechRecognitionCtor;
    webkitSpeechRecognition?: SpeechRecognitionCtor;
  };
  return w.SpeechRecognition || w.webkitSpeechRecognition;
}

// ── Dynamic language detector — detects Devanagari vs Latin/Hinglish ──

export function detectSpeechLanguage(text: string): 'hi-IN' | 'en-IN' {
  if (!text) return 'en-IN';
  // Check for Devanagari Unicode block (Hindi)
  if (/[\u0900-\u097F]/.test(text)) {
    return 'hi-IN';
  }
  return 'en-IN';
}

// ── TTS voice selection — strictly favors calm, natural female personas ──

export function getBestVoice(voices: SpeechSynthesisVoice[], targetLang: string): SpeechSynthesisVoice | null {
  if (!voices || voices.length === 0) return null;

  const langCode = targetLang.toLowerCase().replace('_', '-');
  const langPrefix = langCode.split(/[-_]/)[0]; // e.g. 'en' or 'hi'

  const scoreVoice = (v: SpeechSynthesisVoice): number => {
    const vLang = (v.lang || '').toLowerCase().replace('_', '-');
    const name = (v.name || '').toLowerCase();
    let score = 0;

    // 1. Strict male voice penalty — CyberSaathi is a female assistant persona.
    // Never allow male voices (e.g., Ravi, Rishi, Madhur, Hemant, David, George, Guy).
    if (/\b(male|david|mark|george|ravi|rishi|madhur|hemant|guy|brian|eric|stefan|james|paul|richard|sean|steffan|alex|fred)\b/i.test(name)) {
      return -5000;
    }

    // 2. Language match scoring
    if (vLang === langCode) {
      score += 120;
    } else if (vLang.startsWith(langPrefix)) {
      score += 60;
    } else {
      return -2000; // Incompatible language
    }

    // 3. Female persona bonus
    if (/female/i.test(name)) {
      score += 50;
    }

    // 4. Natural / Neural / Cloud voice priority
    if (/natural|neural|online/i.test(name)) {
      score += 150;
    }
    if (/google/i.test(name)) {
      score += 85;
    }

    // 5. Target curated female personas for Hindi & Indian English
    if (langPrefix === 'hi') {
      if (/swara/i.test(name)) score += 260; // Microsoft Swara Online (Natural) - Hindi
      else if (/kalpana/i.test(name)) score += 160;
      else if (/hindi/i.test(name)) score += 80;
    } else {
      // English / Hinglish
      if (/neerja/i.test(name)) score += 260; // Microsoft Neerja Online (Natural) - English (India)
      else if (/heera/i.test(name)) score += 180;
      else if (/veena/i.test(name)) score += 150;
      else if (/priya|sangeeta/i.test(name)) score += 140;
      else if (/jenny|aria|sonia|natasha|samantha/i.test(name)) score += 110;
      else if (/zira/i.test(name)) score += 40;

      if (/india/i.test(vLang) || /in\b/i.test(vLang)) score += 50; // Indian English preferred
    }

    // 6. Explicitly penalize legacy, flat robotic synthesizers
    if (/desktop|sapi|hazel|susan|espeak/i.test(name)) {
      score -= 75;
    }

    return score;
  };

  let bestVoice: SpeechSynthesisVoice | null = null;
  let bestScore = -1999;

  for (const voice of voices) {
    const score = scoreVoice(voice);
    if (score > bestScore) {
      bestScore = score;
      bestVoice = voice;
    }
  }

  // Fallback 1: If no high-confidence match, find any non-male voice matching langPrefix
  if (!bestVoice || bestScore < 0) {
    bestVoice = voices.find((v) => {
      const vLang = (v.lang || '').toLowerCase();
      const name = (v.name || '').toLowerCase();
      const isMale = /\b(male|david|mark|george|ravi|rishi|madhur|hemant|guy|brian|eric|stefan)\b/i.test(name);
      return !isMale && vLang.startsWith(langPrefix);
    }) || null;
  }

  // Fallback 2: Any voice matching langPrefix if strictly necessary
  if (!bestVoice) {
    bestVoice = voices.find((v) => (v.lang || '').toLowerCase().startsWith(langPrefix)) || null;
  }

  return bestVoice;
}

// ── TTS text cleaning — strip markdown artifacts and format cybersecurity terms ──

export function cleanTextForSpeech(text: string): string {
  if (!text) return '';
  return text
    // Remove code blocks entirely
    .replace(/```[\s\S]*?```/g, '')
    // Remove inline code ticks
    .replace(/`([^`]+)`/g, '$1')
    // Remove markdown links [text](url) → text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    // Remove raw URLs (don't read out full http/https URLs)
    .replace(/https?:\/\/[^\s,)]+/g, '')
    // Remove markdown headers ### Header → Header
    .replace(/^#+\s+/gm, '')
    // Remove blockquotes > Quote → Quote
    .replace(/^>\s+/gm, '')
    // Remove bold/italic markers but keep text
    .replace(/(\*\*\*|___)(.*?)\1/g, '$2')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    .replace(/~~(.*?)~~/g, '$1')
    // Remove bullet points (-, *, •, 1.) at start of lines
    .replace(/^[\s]*[-*+•]\s+/gm, '')
    .replace(/^[\s]*\d+\.\s+/gm, '')
    // Remove emoji sequences
    .replace(/\p{Extended_Pictographic}|\u{FE0F}|\u{200D}/gu, '')
    // Remove horizontal rules (===, ---, ***)
    .replace(/^[-=*_]{3,}$/gm, '')
    // Remove excessive symbols
    .replace(/[-=_]{2,}/g, ' ')
    // Clear pronunciation for security & Indian telecom/cyber terms
    .replace(/\b1930\b/g, 'one nine three zero')
    .replace(/(\w+)\.gov\.in/gi, '$1 dot gov dot in')
    .replace(/\bOTP\b/g, 'O T P')
    .replace(/\bOTPs\b/g, 'O T P s')
    .replace(/\bURL\b/g, 'U R L')
    .replace(/\bURLs\b/g, 'U R L s')
    .replace(/\bSMS\b/g, 'S M S')
    .replace(/\bFIR\b/g, 'F I R')
    .replace(/\bKYC\b/g, 'K Y C')
    .replace(/\bUPI\b/g, 'U P I')
    .replace(/\bAPK\b/g, 'A P K')
    // Convert colons, semicolons, em-dashes to gentle comma pauses for natural cadence
    .replace(/[:;—]/g, ', ')
    .replace(/--+/g, ', ')
    // Add space after Hindi Purna Viram if missing to ensure split works
    .replace(/।/g, '। ')
    // Replace newlines with natural pause markers
    .replace(/\n+/g, '. ')
    // Clean up multiple spaces
    .replace(/\s+/g, ' ')
    // Clean up artifact periods (.. or ... from newline replacement)
    .replace(/\.{2,}/g, '.')
    // Remove leading/trailing periods, commas and spaces
    .replace(/^[\s.,]+/, '')
    .trim();
}

// ── Split text into natural sentence chunks for smoother TTS ──
// Chrome has a ~200-300 char limit where it may cut off; chunking prevents this.

export function splitIntoSentences(text: string): string[] {
  if (text.length < 200) return [text];

  // Split on sentence terminators: . ? ! Hindi purna viram (।) and newlines (never commas)
  const raw = text.split(/(?<=[.?!।\n])\s+/);

  const chunks: string[] = [];
  let current = '';

  for (const sentence of raw) {
    let trimmed = sentence.trim();
    if (!trimmed) continue;

    // Split overly long paragraphs at space boundaries around 220 chars
    while (trimmed.length > 250) {
      if (current) {
        chunks.push(current.trim());
        current = '';
      }
      let splitIndex = trimmed.lastIndexOf(' ', 220);
      if (splitIndex === -1 || splitIndex < 100) splitIndex = 220;
      chunks.push(trimmed.slice(0, splitIndex).trim());
      trimmed = trimmed.slice(splitIndex).trim();
    }

    if (!trimmed) continue;

    if (current && (current.length + trimmed.length + 1) > 250) {
      chunks.push(current.trim());
      current = trimmed;
    } else {
      current = current ? `${current} ${trimmed}` : trimmed;
    }
  }

  if (current.trim()) {
    chunks.push(current.trim());
  }

  return chunks.length > 0 ? chunks : [text];
}

export function useSpeechEngine(options: SpeechEngineOptions): SpeechEngine {
  const { lang } = options;

  // ── State ──
  const [isListening, setIsListening] = useState(false);
  const [voiceSupported, setVoiceSupported] = useState(false);
  const [transcript, setTranscript] = useState('');
  const [voiceError, setVoiceError] = useState('');

  const [isSpeaking, setIsSpeaking] = useState(false);
  const [ttsEnabled, setTtsEnabled] = useState(false);
  const [ttsSupported, setTtsSupported] = useState(false);
  const [activeVoiceName, setActiveVoiceName] = useState('');

  // ── Refs ──
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);
  const isListeningRef = useRef(false);
  const utteranceRef = useRef<SpeechSynthesisUtterance | null>(null);
  const ttsQueueRef = useRef<string[]>([]);
  const ttsCancelledRef = useRef(false);
  const ttsSessionRef = useRef(0);
  const keepAliveTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const silenceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Transcript tracking for continuous voice typing
  const baseTranscriptRef = useRef('');
  const finalTranscriptRef = useRef('');

  // ── Deterministic Voice Cache ──
  const voicesRef = useRef<SpeechSynthesisVoice[]>([]);
  const preferredHindiVoiceRef = useRef<SpeechSynthesisVoice | null>(null);
  const preferredEnglishVoiceRef = useRef<SpeechSynthesisVoice | null>(null);
  const sessionVoiceRef = useRef<SpeechSynthesisVoice | null>(null);

  // Stop speaking helper (needed early for microphone mutual-exclusion)
  const clearKeepAlive = useCallback(() => {
    if (keepAliveTimerRef.current) {
      clearInterval(keepAliveTimerRef.current);
      keepAliveTimerRef.current = null;
    }
  }, []);

  const stopSpeaking = useCallback(() => {
    ttsSessionRef.current += 1;
    ttsCancelledRef.current = true;
    ttsQueueRef.current = [];
    clearKeepAlive();
    try {
      window.speechSynthesis?.cancel();
    } catch {
      // ignore
    }
    utteranceRef.current = null;
    setIsSpeaking(false);
  }, [clearKeepAlive]);

  // Enumerate voices once and resolve preferred female voices per language
  const refreshVoices = useCallback(() => {
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) return;
    const v = window.speechSynthesis.getVoices();
    if (!v || v.length === 0) return;

    voicesRef.current = v;
    const bestHi = getBestVoice(v, 'hi-IN');
    const bestEn = getBestVoice(v, 'en-IN');
    preferredHindiVoiceRef.current = bestHi;
    preferredEnglishVoiceRef.current = bestEn;

    const active = lang.toLowerCase().startsWith('hi') ? bestHi : bestEn;
    if (active) {
      setActiveVoiceName(active.name);
    }
  }, [lang]);

  // Check browser support and pre-cache voices on mount
  useEffect(() => {
    const SR = getSpeechRecognitionCtor();
    setVoiceSupported(!!SR);
    const hasTts = typeof window !== 'undefined' && 'speechSynthesis' in window;
    setTtsSupported(hasTts);

    if (hasTts) {
      refreshVoices();
      if (typeof window.speechSynthesis.addEventListener === 'function') {
        window.speechSynthesis.addEventListener('voiceschanged', refreshVoices);
      } else {
        window.speechSynthesis.onvoiceschanged = refreshVoices;
      }
      return () => {
        if (typeof window.speechSynthesis?.removeEventListener === 'function') {
          window.speechSynthesis.removeEventListener('voiceschanged', refreshVoices);
        } else if (window.speechSynthesis) {
          window.speechSynthesis.onvoiceschanged = null;
        }
      };
    }
  }, [refreshVoices]);

  // Deterministically switch active voice identity when user switches language in UI
  useEffect(() => {
    const isHi = lang.toLowerCase().startsWith('hi');
    const target = isHi ? preferredHindiVoiceRef.current : preferredEnglishVoiceRef.current;
    if (target) {
      setActiveVoiceName(target.name);
    } else if (voicesRef.current.length > 0) {
      const fallback = getBestVoice(voicesRef.current, isHi ? 'hi-IN' : 'en-IN');
      if (fallback) setActiveVoiceName(fallback.name);
    }
  }, [lang]);

  // ── STT Controls ──

  const destroyRecognition = useCallback(() => {
    if (silenceTimerRef.current) {
      clearTimeout(silenceTimerRef.current);
      silenceTimerRef.current = null;
    }
    if (recognitionRef.current) {
      recognitionRef.current.onstart = null;
      recognitionRef.current.onaudiostart = null;
      recognitionRef.current.onsoundstart = null;
      recognitionRef.current.onspeechstart = null;
      recognitionRef.current.onspeechend = null;
      recognitionRef.current.onsoundend = null;
      recognitionRef.current.onaudioend = null;
      recognitionRef.current.onresult = null;
      recognitionRef.current.onerror = null;
      recognitionRef.current.onend = null;
      
      try {
        recognitionRef.current.abort();
      } catch {
        // ignore
      }
      recognitionRef.current = null;
    }
    isListeningRef.current = false;
    setIsListening(false);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      destroyRecognition();
      ttsCancelledRef.current = true;
      ttsQueueRef.current = [];
      clearKeepAlive();
      if (utteranceRef.current) {
        window.speechSynthesis?.cancel();
        utteranceRef.current = null;
      }
    };
  }, [destroyRecognition, clearKeepAlive]);

  const stopListening = useCallback(() => {
    if (silenceTimerRef.current) {
      clearTimeout(silenceTimerRef.current);
      silenceTimerRef.current = null;
    }

    if (recognitionRef.current) {
      try {
        recognitionRef.current.stop();
      } catch {
        // ignore
      }
    }

    isListeningRef.current = false;
    setIsListening(false);
  }, []);

  const startListening = useCallback(() => {
    const SR = getSpeechRecognitionCtor();
    if (!SR || !voiceSupported) {
      setVoiceError('Voice input is not supported in this browser.');
      return;
    }

    // Stop speaking immediately if assistant is active (mutual-exclusion)
    stopSpeaking();

    if (isListeningRef.current) {
      return;
    }

    // Completely destroy any previous zombie instance
    destroyRecognition();
    setVoiceError('');

    const recognition = new SR();
    
    // PRODUCTION STT CONFIG: continuous listening with progressive interim results
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.maxAlternatives = 1;
    recognition.lang = lang;

    // Capture baseline text before speech begins
    baseTranscriptRef.current = transcript.trim() ? transcript.trim() + ' ' : '';
    finalTranscriptRef.current = '';

    recognition.onstart = () => {
      isListeningRef.current = true;
      setIsListening(true);
      setVoiceError('');
    };

    recognition.onresult = (event: SpeechRecognitionResultEventLike) => {
      let currentFinal = '';
      let currentInterim = '';

      for (let i = 0; i < event.results.length; ++i) {
        const res = event.results[i];
        const text = res[0]?.transcript || '';
        if (res.isFinal) {
          currentFinal += text;
        } else {
          currentInterim += text;
        }
      }

      finalTranscriptRef.current = currentFinal;
      const full = (baseTranscriptRef.current + currentFinal + (currentInterim ? ' ' + currentInterim : '')).trim();
      setTranscript(full);

      // Bounded silence detection: 2.5s of calm silence after speech automatically stops
      if (silenceTimerRef.current) {
        clearTimeout(silenceTimerRef.current);
      }
      silenceTimerRef.current = setTimeout(() => {
        stopListening();
      }, 2500);
    };

    recognition.onspeechstart = () => {
      if (silenceTimerRef.current) {
        clearTimeout(silenceTimerRef.current);
        silenceTimerRef.current = null;
      }
    };

    recognition.onspeechend = () => {
      // Natural speech clause ended; 1.5s boundary before finalizing
      if (silenceTimerRef.current) {
        clearTimeout(silenceTimerRef.current);
      }
      silenceTimerRef.current = setTimeout(() => {
        stopListening();
      }, 1500);
    };

    recognition.onerror = (event: SpeechRecognitionErrorEventLike) => {
      if (silenceTimerRef.current) {
        clearTimeout(silenceTimerRef.current);
        silenceTimerRef.current = null;
      }

      if (event.error === 'aborted') {
        isListeningRef.current = false;
        setIsListening(false);
        return;
      }

      if (event.error === 'no-speech') {
        // Harmless silence — user paused or ambient room noise did not form words
        isListeningRef.current = false;
        setIsListening(false);
        return;
      }

      isListeningRef.current = false;
      setIsListening(false);

      switch (event.error) {
        case 'not-allowed':
          setVoiceError('Microphone permission denied.');
          break;
        case 'audio-capture':
          setVoiceError('No microphone found.');
          break;
        case 'network':
          setVoiceError('Network error during voice recognition.');
          break;
        default:
          setVoiceError(`Voice error: ${event.error}`);
      }
    };

    recognition.onend = () => {
      if (silenceTimerRef.current) {
        clearTimeout(silenceTimerRef.current);
        silenceTimerRef.current = null;
      }
      // Commit final text safely into state
      const committed = (baseTranscriptRef.current + finalTranscriptRef.current).trim();
      if (committed) {
        setTranscript(committed);
      }
      isListeningRef.current = false;
      setIsListening(false);
      if (recognitionRef.current === recognition) {
        recognitionRef.current = null;
      }
    };

    recognitionRef.current = recognition;
    
    // Start immediately without artificial setTimeout latency
    try {
      recognition.start();
    } catch {
      isListeningRef.current = false;
      setIsListening(false);
    }
  }, [voiceSupported, lang, transcript, destroyRecognition, stopSpeaking, stopListening]);

  const toggleListening = useCallback(() => {
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  }, [isListening, startListening, stopListening]);

  const clearTranscript = useCallback(() => {
    setTranscript('');
    baseTranscriptRef.current = '';
    finalTranscriptRef.current = '';
  }, []);

  const clearVoiceError = useCallback(() => {
    setVoiceError('');
  }, []);

  // ── TTS Controls — Session-tracked with Chrome keepalive & deterministic voice ──

  const startKeepAlive = useCallback(() => {
    clearKeepAlive();
    // Chrome stops TTS after 15 seconds without firing onend. A 10s pause/resume pulse keeps it alive.
    keepAliveTimerRef.current = setInterval(() => {
      if (typeof window !== 'undefined' && window.speechSynthesis && window.speechSynthesis.speaking) {
        window.speechSynthesis.pause();
        window.speechSynthesis.resume();
      }
    }, 10000);
  }, [clearKeepAlive]);

  const speakChunkQueue = useCallback((sessionId: number) => {
    // If user cancelled or another session started, abort immediately
    if (ttsCancelledRef.current || ttsSessionRef.current !== sessionId) {
      setIsSpeaking(false);
      clearKeepAlive();
      return;
    }

    if (ttsQueueRef.current.length === 0) {
      setIsSpeaking(false);
      utteranceRef.current = null;
      clearKeepAlive();
      return;
    }

    const chunk = ttsQueueRef.current.shift()!;
    if (!chunk || !chunk.trim()) {
      speakChunkQueue(sessionId);
      return;
    }
    
    const utterance = new SpeechSynthesisUtterance(chunk);
    utteranceRef.current = utterance;

    // GC Bug Fix: retain up to 5 utterances to prevent garbage collection mid-speech without memory leaks
    const win = window as unknown as { __utterances?: SpeechSynthesisUtterance[] };
    win.__utterances = win.__utterances || [];
    win.__utterances.push(utterance);
    if (win.__utterances.length > 5) {
      win.__utterances.shift();
    }

    // ── REUSE THE EXACT SAME SELECTED VOICE ACROSS ALL CHUNKS IN THIS RESPONSE ──
    const voice = sessionVoiceRef.current;
    if (voice) {
      utterance.voice = voice;
      utterance.lang = voice.lang || 'en-IN';
    }

    const isHindi = (utterance.lang || '').toLowerCase().startsWith('hi');
    utterance.rate = isHindi ? 0.90 : 0.94;
    utterance.pitch = isHindi ? 1.02 : 1.0;
    utterance.volume = 1.0;

    utterance.onstart = () => {
      if (ttsSessionRef.current === sessionId) {
        setIsSpeaking(true);
        startKeepAlive();
      }
    };

    utterance.onend = () => {
      if (ttsSessionRef.current !== sessionId || ttsCancelledRef.current) return;
      
      if (ttsQueueRef.current.length > 0) {
        if (window.speechSynthesis.paused) {
          window.speechSynthesis.resume();
        }
        speakChunkQueue(sessionId);
      } else {
        setIsSpeaking(false);
        utteranceRef.current = null;
        clearKeepAlive();
      }
    };

    utterance.onerror = (e) => {
      if (ttsSessionRef.current !== sessionId) return;

      if (e.error !== 'interrupted' && e.error !== 'canceled') {
        console.warn('[TTS] Speech error on chunk:', e.error);
      }

      if (ttsQueueRef.current.length > 0 && !ttsCancelledRef.current) {
        speakChunkQueue(sessionId);
      } else {
        setIsSpeaking(false);
        utteranceRef.current = null;
        clearKeepAlive();
      }
    };

    try {
      if (window.speechSynthesis.paused) {
        window.speechSynthesis.resume();
      }
      window.speechSynthesis.speak(utterance);
    } catch (speakErr) {
      console.warn('[TTS] Failed to execute speak:', speakErr);
      if (ttsQueueRef.current.length > 0 && !ttsCancelledRef.current) {
        speakChunkQueue(sessionId);
      } else {
        setIsSpeaking(false);
        clearKeepAlive();
      }
    }
  }, [clearKeepAlive, startKeepAlive]);

  const speakText = useCallback((text: string) => {
    if (!ttsEnabled || !window.speechSynthesis) return;

    // Increment session ID to cancel out any incoming callbacks from previous utterances
    ttsSessionRef.current += 1;
    const currentSession = ttsSessionRef.current;

    ttsCancelledRef.current = false;
    utteranceRef.current = null;
    clearKeepAlive();

    try {
      window.speechSynthesis.cancel();
    } catch {
      // ignore
    }

    const clean = cleanTextForSpeech(text);
    if (!clean) return;

    // ── SELECT PREFERRED FEMALE VOICE ONCE FOR THE ENTIRE UTTERANCE ──
    const targetLang = detectSpeechLanguage(clean);
    const isHindi = targetLang.startsWith('hi');
    const chosenVoice = isHindi
      ? (preferredHindiVoiceRef.current || getBestVoice(voicesRef.current, 'hi-IN'))
      : (preferredEnglishVoiceRef.current || getBestVoice(voicesRef.current, 'en-IN'));

    sessionVoiceRef.current = chosenVoice;
    if (chosenVoice) {
      setActiveVoiceName(chosenVoice.name);
    }

    // Split into natural sentence chunks
    const chunks = splitIntoSentences(clean);
    ttsQueueRef.current = chunks;

    // Speak first chunk directly
    speakChunkQueue(currentSession);
  }, [ttsEnabled, speakChunkQueue, clearKeepAlive]);

  const previewVoice = useCallback(() => {
    const isHindi = lang.toLowerCase().startsWith('hi');
    const sampleText = isHindi
      ? 'नमस्ते, मैं साइबर साथी हूँ। आपकी ऑनलाइन सुरक्षा में कैसे मदद कर सकती हूँ?'
      : "Hello, I am CyberSaathi, your digital safety assistant. How can I help you today?";
    speakText(sampleText);
  }, [lang, speakText]);

  return {
    isListening,
    voiceSupported,
    transcript,
    setTranscript,
    startListening,
    stopListening,
    toggleListening,
    clearTranscript,

    isSpeaking,
    ttsEnabled,
    setTtsEnabled,
    ttsSupported,
    speakText,
    stopSpeaking,
    activeVoiceName,
    previewVoice,

    voiceError,
    clearVoiceError,
  };
}
