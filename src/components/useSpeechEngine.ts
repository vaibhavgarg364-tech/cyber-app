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

  voiceError: string;
  clearVoiceError: () => void;
}

// ── Minimal Web Speech API typings (not in lib.dom for all TS versions) ──

interface SpeechRecognitionResultEventLike {
  results: ArrayLike<ArrayLike<{ transcript: string }>>;
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

// ── TTS text cleaning — remove all markdown artifacts for natural speech ──

function cleanTextForSpeech(text: string): string {
  return text
    // Remove code blocks entirely (not relevant for speech)
    .replace(/```[\s\S]*?```/g, '')
    // Remove inline code ticks
    .replace(/`[^`]+`/g, (match) => match.slice(1, -1))
    // Remove markdown links [text](url) → text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    // Remove raw URLs (don't read them aloud)
    .replace(/https?:\/\/[^\s,)]+/g, '')
    // Remove markdown headers ### Header → Header
    .replace(/^#+\s+/gm, '')
    // Remove bold/italic markers but keep text
    .replace(/(\*\*\*|___)(.*?)\1/g, '$2')
    .replace(/(\*\*|__)(.*?)\1/g, '$2')
    .replace(/(\*|_)(.*?)\1/g, '$2')
    // Remove bullet points (-, *, •, 1.) at start of lines
    .replace(/^[\s]*[-*+•]\s+/gm, '')
    .replace(/^[\s]*\d+\.\s+/gm, '')
    // Remove emoji sequences (they cause TTS to say "emoji" or garble)
    .replace(/\p{Extended_Pictographic}|\u{FE0F}|\u{200D}/gu, '')
    // Remove horizontal rules (===, ---, ***)
    .replace(/^[-=*_]{3,}$/gm, '')
    // Remove excessive symbols
    .replace(/[-=_]{2,}/g, ' ')
    // Clean up "cybercrime.gov.in" → "cybercrime dot gov dot in" for clarity
    .replace(/(\w+)\.gov\.in/g, '$1 dot gov dot in')
    // Add space after Hindi Purna Viram if missing to ensure split works
    .replace(/।/g, '। ')
    // Replace newlines with natural pause markers
    .replace(/\n+/g, '. ')
    // Clean up multiple spaces
    .replace(/\s+/g, ' ')
    // Clean up artifact periods (.. or ... from newline replacement)
    .replace(/\.{2,}/g, '.')
    // Remove leading/trailing periods and spaces
    .replace(/^\.\s*/, '')
    .trim();
}

// ── Split text into natural sentence chunks for smoother TTS ──
// Chrome has a ~200-300 char limit where it may cut off; chunking prevents this.

function splitIntoSentences(text: string): string[] {
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

  // ── Refs ──
  const recognitionRef = useRef<SpeechRecognitionLike | null>(null);
  const utteranceRef = useRef<SpeechSynthesisUtterance | null>(null);
  const ttsQueueRef = useRef<string[]>([]);
  const ttsCancelledRef = useRef(false);
  const ttsSessionRef = useRef(0);
  const keepAliveTimerRef = useRef<any>(null);

  // Check browser support on mount
  useEffect(() => {
    const SR = getSpeechRecognitionCtor();
    setVoiceSupported(!!SR);
    setTtsSupported(typeof window !== 'undefined' && 'speechSynthesis' in window);
  }, []);

  // ── STT Controls ──

  const destroyRecognition = useCallback(() => {
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
    setIsListening(false);
  }, []);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      destroyRecognition();
      ttsCancelledRef.current = true;
      ttsQueueRef.current = [];
      if (utteranceRef.current) {
        window.speechSynthesis?.cancel();
        utteranceRef.current = null;
      }
    };
  }, [destroyRecognition]);

  const startListening = useCallback(() => {
    const SR = getSpeechRecognitionCtor();
    if (!SR || !voiceSupported) {
      setVoiceError('Voice input is not supported in this browser.');
      return;
    }

    // Completely destroy any existing instance
    destroyRecognition();
    setVoiceError('');

    const recognition = new SR();
    
    // MINIMAL CONFIG
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.maxAlternatives = 1;
    recognition.lang = lang;

    recognition.onstart = () => {
      setIsListening(true);
      setVoiceError('');
    };

    recognition.onresult = (event: SpeechRecognitionResultEventLike) => {
      const text = event.results[0][0].transcript;
      setTranscript(text);
    };

    recognition.onerror = (event: SpeechRecognitionErrorEventLike) => {
      setIsListening(false);
      if (event.error === 'aborted') return;

      switch (event.error) {
        case 'not-allowed':
          setVoiceError('Microphone permission denied.');
          break;
        case 'no-speech':
          // Silent — user just didn't speak, not an error
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
      setIsListening(false);
      if (recognitionRef.current === recognition) {
        recognitionRef.current = null;
      }
    };

    recognitionRef.current = recognition;
    
    // Small delay to avoid Chrome race condition
    setTimeout(() => {
      try {
        recognitionRef.current?.start();
      } catch {
        setIsListening(false);
      }
    }, 150);
    
  }, [voiceSupported, lang, destroyRecognition]);

  const stopListening = useCallback(() => {
    if (recognitionRef.current) {
      try {
        recognitionRef.current.stop();
      } catch {
        setIsListening(false);
      }
    } else {
      setIsListening(false);
    }
  }, []);

  const toggleListening = useCallback(() => {
    if (isListening) {
      stopListening();
    } else {
      startListening();
    }
  }, [isListening, startListening, stopListening]);

  const clearTranscript = useCallback(() => {
    setTranscript('');
  }, []);

  const clearVoiceError = useCallback(() => {
    setVoiceError('');
  }, []);

  // ── TTS Controls — Sentence-chunked with voice selection ──

  // ── TTS Controls — Session-tracked with Chrome keepalive ──

  const clearKeepAlive = useCallback(() => {
    if (keepAliveTimerRef.current) {
      clearInterval(keepAliveTimerRef.current);
      keepAliveTimerRef.current = null;
    }
  }, []);

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
      // Empty chunk, skip to next immediately
      speakChunkQueue(sessionId);
      return;
    }
    
    const utterance = new SpeechSynthesisUtterance(chunk);
    
    // GC Bug Fix: Retain reference in window so Chrome doesn't garbage collect mid-speech
    const win = window as any;
    win.__utterances = win.__utterances || [];
    win.__utterances.push(utterance);
    
    utteranceRef.current = utterance;

    utterance.lang = lang;
    utterance.rate = lang.startsWith('hi') ? 0.9 : 0.95;
    utterance.pitch = 1.0;
    utterance.volume = 1.0;

    // Voice selection — prefer natural/enhanced voices
    const voices = window.speechSynthesis.getVoices();
    if (voices.length > 0) {
      const langPrefix = lang.split('-')[0];
      const preferred =
        voices.find((v) => v.lang === lang && /google|microsoft|natural/i.test(v.name)) ||
        voices.find((v) => v.lang === lang) ||
        voices.find((v) => v.lang.startsWith(langPrefix));
      if (preferred) utterance.voice = preferred;
    }

    utterance.onstart = () => {
      if (ttsSessionRef.current === sessionId) {
        setIsSpeaking(true);
        startKeepAlive();
      }
    };

    utterance.onend = () => {
      if (ttsSessionRef.current !== sessionId || ttsCancelledRef.current) return;
      
      // Speak next chunk in queue with a brief conversational pause
      if (ttsQueueRef.current.length > 0) {
        if (window.speechSynthesis.paused) {
          window.speechSynthesis.resume();
        }
        setTimeout(() => speakChunkQueue(sessionId), 60);
      } else {
        setIsSpeaking(false);
        utteranceRef.current = null;
        clearKeepAlive();
      }
    };

    utterance.onerror = (e) => {
      // Ignore errors belonging to older cancelled sessions
      if (ttsSessionRef.current !== sessionId) return;

      if (e.error !== 'interrupted' && e.error !== 'canceled') {
        console.warn('[TTS] Speech error on chunk:', e.error);
      }

      // RESILIENCY FIX: If an individual chunk fails or times out, DO NOT abort the entire queue!
      // Attempt to proceed with the remaining chunks so the rest of the text is not lost.
      if (ttsQueueRef.current.length > 0 && !ttsCancelledRef.current) {
        setTimeout(() => speakChunkQueue(sessionId), 80);
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
        setTimeout(() => speakChunkQueue(sessionId), 80);
      } else {
        setIsSpeaking(false);
        clearKeepAlive();
      }
    }
  }, [lang, clearKeepAlive, startKeepAlive]);

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

    // Split into natural sentence chunks
    const chunks = splitIntoSentences(clean);
    ttsQueueRef.current = chunks;

    const doSpeak = () => {
      if (ttsSessionRef.current !== currentSession || ttsCancelledRef.current) return;
      speakChunkQueue(currentSession);
    };

    // Ensure voices are initialized before speaking
    const voices = window.speechSynthesis.getVoices();
    if (voices.length > 0) {
      // Small tick to ensure previous cancel completed in browser thread
      setTimeout(doSpeak, 30);
    } else {
      const onReady = () => {
        window.speechSynthesis.removeEventListener('voiceschanged', onReady);
        doSpeak();
      };
      window.speechSynthesis.addEventListener('voiceschanged', onReady);
      setTimeout(() => {
        window.speechSynthesis.removeEventListener('voiceschanged', onReady);
        if (!window.speechSynthesis.speaking) doSpeak();
      }, 800);
    }
  }, [ttsEnabled, speakChunkQueue, clearKeepAlive]);

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

    voiceError,
    clearVoiceError,
  };
}
