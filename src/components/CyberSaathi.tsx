/**
 * CyberSaathi — Production-grade cyber emergency assistant.
 *
 * This is the orchestrator. It owns:
 *   - Chat state (messages, loading, error)
 *   - Message send flow with timeout + offline detection
 *   - Duplicate-send prevention
 *   - Conversation history trimming for API cost efficiency
 *   - Integration with useSpeechEngine (voice I/O)
 *   - Rendering via CyberSaathiUI sub-components
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useLang } from '../context/LanguageContext';
import { chatWithSaathi } from '../api';
import { useSpeechEngine } from './useSpeechEngine';
import {
  ChatHeader,
  MessageBubble,
  TypingIndicator,
  EmergencyBanner,
  ChatInput,
  ErrorDisplay,
  FloatingButton,
  type Message,
} from './CyberSaathiUI';

// ─── Types ──────────────────────────────────────────────────────────────────

type ChatLanguage = 'English' | 'हिंदी';

interface CyberSaathiProps {
  autoOpen?: boolean;
  initialMode?: 'emergency' | 'normal';
  onOpenChange?: (open: boolean) => void;
}

// ─── Constants ──────────────────────────────────────────────────────────────

/** Max history turns sent to API (keeps token cost + latency low). */
const MAX_HISTORY_TURNS = 8;

/** Request timeout in ms. */
const REQUEST_TIMEOUT_MS = 45_000;

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Trim history to the most recent N turns, preserving context. */
function trimHistory(messages: Message[]): { role: string; content: string }[] {
  const relevant = messages.slice(-MAX_HISTORY_TURNS);
  return relevant.map((m) => ({
    role: m.role,
    // Truncate very long individual messages to save tokens
    content: m.content.length > 800 ? m.content.slice(0, 800) + '…' : m.content,
  }));
}

/** Wrap a promise with a timeout. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('Request timed out. Please try again.')),
      ms
    );
    promise.then(
      (val) => { clearTimeout(timer); resolve(val); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

// ─── Component ──────────────────────────────────────────────────────────────

export default function CyberSaathi({
  autoOpen = false,
  initialMode = 'normal',
  onOpenChange,
}: CyberSaathiProps) {
  const { lang, t } = useLang();

  // ── Chat state ──
  const [open, setOpen] = useState(autoOpen);
  const [selectedLanguage, setSelectedLanguage] = useState<ChatLanguage>(
    lang === 'en' ? 'English' : 'हिंदी'
  );
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        initialMode === 'emergency'
          ? t(
              'I am here with you. Tell me what happened — I will guide you step by step.',
              'मैं आपके साथ हूँ। बताइए क्या हुआ — मैं आपको कदम-दर-कदम मार्गदर्शन दूँगा।'
            )
          : t(
              'Hello! I am CyberSaathi — your personal cyber safety assistant. How can I help you today?',
              'नमस्ते! मैं CyberSaathi हूँ — आपका साइबर सुरक्षा सहायक। आज मैं आपकी कैसे मदद कर सकता हूँ?'
            ),
      timestamp: new Date(),
    },
  ]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isOffline, setIsOffline] = useState(!navigator.onLine);
  const [dynamicEmergency, setDynamicEmergency] = useState(initialMode === 'emergency');

  // ── Refs ──
  const bottomRef = useRef<HTMLDivElement>(null);
  const loadingRef = useRef(false);
  const lastSentRef = useRef(''); // duplicate-send prevention

  useEffect(() => {
    loadingRef.current = loading;
  }, [loading]);

  // ── Offline detection ──
  useEffect(() => {
    const goOffline = () => setIsOffline(true);
    const goOnline = () => setIsOffline(false);
    window.addEventListener('offline', goOffline);
    window.addEventListener('online', goOnline);
    return () => {
      window.removeEventListener('offline', goOffline);
      window.removeEventListener('online', goOnline);
    };
  }, []);

  // ── Voice engine ──
  const speechLang = selectedLanguage === 'English' ? 'en-IN' : 'hi-IN';

  const speech = useSpeechEngine({
    lang: speechLang,
  });

  // ── Sync language ──
  useEffect(() => {
    setSelectedLanguage(lang === 'en' ? 'English' : 'हिंदी');
  }, [lang]);

  // ── Auto-open ──
  useEffect(() => {
    setOpen(autoOpen);
  }, [autoOpen]);

  // ── Auto-scroll (smooth, debounced) ──
  useEffect(() => {
    requestAnimationFrame(() => {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    });
  }, [messages, loading]);

  // ── Open/close handlers ──
  const openChat = useCallback(() => {
    setOpen(true);
    onOpenChange?.(true);
  }, [onOpenChange]);

  const closeChat = useCallback(() => {
    setOpen(false);
    onOpenChange?.(false);
    speech.stopListening();
    speech.stopSpeaking();
  }, [onOpenChange, speech]);

  useEffect(() => {
    onOpenChange?.(open);
  }, [open, onOpenChange]);

  // ── Message send (with timeout, offline check, duplicate prevention) ──

  const sendMessageWithText = useCallback(
    async (textToSend: string) => {
      const trimmed = textToSend.trim();
      if (!trimmed || loadingRef.current) return;

      // Duplicate-send prevention (same message within rapid succession)
      if (trimmed === lastSentRef.current) return;
      lastSentRef.current = trimmed;

      // Offline check
      if (!navigator.onLine) {
        setError(t(
          'You appear to be offline. Please check your connection.',
          'आप ऑफ़लाइन प्रतीत होते हैं। कृपया अपना कनेक्शन जांचें।'
        ));
        return;
      }

      // Stop listening if still active
      if (speech.isListening) {
        speech.stopListening();
      }

      const newUserMessage: Message = { role: 'user', content: trimmed, timestamp: new Date() };

      // 1. Update messages state
      setMessages((prev) => [...prev, newUserMessage]);

      // 2. Clear textarea
      try {
        speech.clearTranscript();
        setError('');
        if (speech.isListening) {
          speech.stopListening();
        }
      } catch {
        // Non-fatal voice cleanup — swallow silently
      }

      setLoading(true);
      loadingRef.current = true;

      try {
        // Trim history intelligently to reduce token waste
        const currentHistory = trimHistory([...messages, newUserMessage]);

        const data = await withTimeout(
          chatWithSaathi(trimmed, currentHistory, selectedLanguage),
          REQUEST_TIMEOUT_MS
        );

        const aiResponse =
          data.response ||
          (selectedLanguage === 'English'
            ? 'I apologize — something went wrong. Please try again.'
            : 'क्षमा करें — कुछ गड़बड़ हो गई। कृपया दोबारा प्रयास करें।');

        // Update emergency mode from API response
        if (data.isEmergency) {
          setDynamicEmergency(true);
        }

        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: aiResponse,
            timestamp: new Date(),
            quickActions: Array.isArray(data.quickActions) ? data.quickActions : [],
          },
        ]);

        speech.speakText(aiResponse);
      } catch (err) {
        console.error('[CyberSaathi] API error:', err);
        // Show a calm, user-friendly fallback — never raw error dumps
        const friendlyMsg =
          err instanceof Error
            ? err.message
            : t(
                'CyberSaathi is temporarily unavailable. Please try again shortly.',
                'CyberSaathi अस्थायी रूप से अनुपलब्ध है। कृपया कुछ देर बाद पुनः प्रयास करें।'
              );
            
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            content: friendlyMsg,
            timestamp: new Date(),
          },
        ]);
        
        setError('');
      } finally {
        setLoading(false);
        loadingRef.current = false;
        // Reset duplicate guard after a short cooldown
        setTimeout(() => { lastSentRef.current = ''; }, 1000);
      }
    },
    [selectedLanguage, t, speech, messages]
  );

  // ── Manual send (from input or Enter key) ──

  const handleSend = useCallback(() => {
    const trimmed = speech.transcript.trim();
    if (!trimmed || loading) return;

    if (speech.isListening) {
      speech.stopListening();
    }

    sendMessageWithText(trimmed);
  }, [speech, loading, sendMessageWithText]);

  // ── Retry last failed message ──
  const handleRetry = useCallback(() => {
    // Find the last user message and re-send it
    const lastUserMsg = [...messages].reverse().find((m) => m.role === 'user');
    if (lastUserMsg) {
      // Remove the failed assistant response
      setMessages((prev) => {
        const last = prev[prev.length - 1];
        if (last?.role === 'assistant') {
          return prev.slice(0, -1);
        }
        return prev;
      });
      lastSentRef.current = ''; // Allow re-send
      sendMessageWithText(lastUserMsg.content);
    }
  }, [messages, sendMessageWithText]);

  // ── TTS toggle ──

  const handleToggleTts = useCallback(() => {
    const next = !speech.ttsEnabled;
    speech.setTtsEnabled(next);
    if (!next) {
      speech.stopSpeaking();
    }
  }, [speech]);

  // ── Combined error ──
  const displayError = isOffline
    ? t('You are offline. Messages will send when reconnected.', 'आप ऑफ़लाइन हैं।')
    : error || speech.voiceError;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <>
      {/* Floating Action Button */}
      {!open && (
        <FloatingButton
          isEmergency={initialMode === 'emergency'}
          onClick={openChat}
        />
      )}

      {/* Chat Window */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 24, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 16, scale: 0.96 }}
            transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
            className="cs-window"
          >
            {/* Header */}
            <ChatHeader
              isEmergency={dynamicEmergency}
              ttsEnabled={speech.ttsEnabled}
              isSpeaking={speech.isSpeaking}
              ttsSupported={speech.ttsSupported}
              onToggleTts={handleToggleTts}
              onStopSpeaking={speech.stopSpeaking}
              onClose={closeChat}
              t={t}
            />

            {/* Messages */}
            <div className="cs-messages">
              {messages.map((msg, i) => (
                <MessageBubble key={i} msg={msg} index={i} />
              ))}
              {loading && <TypingIndicator />}
              <div ref={bottomRef} />
            </div>

            {/* Error display */}
            {displayError && <ErrorDisplay error={displayError} onRetry={handleRetry} />}

            {/* Emergency banner */}
            <EmergencyBanner t={t} />

            {/* Input area */}
            <ChatInput
              input={speech.transcript}
              isListening={speech.isListening}
              isLoading={loading}
              voiceSupported={speech.voiceSupported}
              onInputChange={speech.setTranscript}
              onSend={handleSend}
              onToggleMic={speech.toggleListening}
              t={t}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
