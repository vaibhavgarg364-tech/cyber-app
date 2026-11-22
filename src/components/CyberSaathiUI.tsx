/**
 * CyberSaathiUI — Pure visual sub-components for CyberSaathi.
 *
 * No business logic. No API calls. No voice logic.
 * These components receive props and render beautifully.
 */

import { useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bot, X, Send, Mic, Square, Volume2, VolumeX,
  AlertTriangle, Loader2, ShieldCheck, ChevronRight, RefreshCw,
} from 'lucide-react';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface QuickAction {
  type: string;
  target: string;
  label: string;
}

export interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  quickActions?: QuickAction[];
}

// ─── Chat Header ────────────────────────────────────────────────────────────

interface ChatHeaderProps {
  isEmergency: boolean;
  ttsEnabled: boolean;
  isSpeaking: boolean;
  ttsSupported: boolean;
  activeVoiceName?: string;
  onToggleTts: () => void;
  onStopSpeaking: () => void;
  onClose: () => void;
  t: (en: string, hi: string) => string;
}

export function ChatHeader({
  isEmergency, ttsEnabled, isSpeaking, ttsSupported, activeVoiceName,
  onToggleTts, onStopSpeaking, onClose, t,
}: ChatHeaderProps) {
  return (
    <div className="cs-header">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_20%_50%,rgba(0,224,255,0.14),transparent_50%)] opacity-70" />

      <div className="relative z-10 flex items-center gap-3">
        {/* Avatar with animated ring */}
        <div className="cs-avatar">
          <div className="cs-avatar-ring" />
          <ShieldCheck className="w-5 h-5 text-cyan-400 relative z-10" />
        </div>
        <div>
          <p className="text-white font-semibold text-sm tracking-tight">CyberSaathi</p>
          <div className="flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${
              isEmergency ? 'bg-orange-400' : 'bg-emerald-400'
            }`} />
            <p className={`text-[11px] font-medium ${
              isEmergency ? 'text-orange-400' : 'text-emerald-400'
            }`}>
              {isEmergency
                ? t('Emergency Mode', 'आपातकालीन मोड')
                : t('Active', 'सक्रिय')}
            </p>
          </div>
        </div>
      </div>

      <div className="relative z-10 flex items-center gap-1.5">
        {/* TTS toggle */}
        {ttsSupported && (
          <button
            type="button"
            onClick={() => {
              if (isSpeaking) {
                onStopSpeaking();
              }
              onToggleTts();
            }}
            className={`p-1.5 rounded-lg transition-colors ${
              ttsEnabled
                ? 'text-cyan-400 bg-cyan-500/15'
                : 'text-slate-500 hover:text-slate-300'
            }`}
            aria-label={t('Toggle voice output', 'आवाज़ आउटपुट टॉगल')}
            title={
              ttsEnabled
                ? (activeVoiceName
                    ? `${t('Voice responses: ON', 'आवाज़ जवाब: चालू')} (${activeVoiceName})`
                    : t('Voice responses: ON', 'आवाज़ जवाब: चालू'))
                : t('Voice responses: OFF', 'आवाज़ जवाब: बंद')
            }
          >
            {ttsEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>
        )}

        {/* Speaking indicator */}
        {isSpeaking && (
          <button
            type="button"
            onClick={onStopSpeaking}
            className="p-1.5 rounded-lg text-cyan-400 bg-cyan-500/15 animate-pulse"
            title={t('Stop speaking', 'बोलना बंद करें')}
          >
            <Square className="w-3.5 h-3.5 fill-current" />
          </button>
        )}

        {/* Close */}
        <button
          type="button"
          onClick={onClose}
          className="p-1.5 text-slate-500 hover:text-white transition-colors"
          aria-label={t('Close chat', 'चैट बंद करें')}
        >
          <X className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
}

// ─── Message Bubble ─────────────────────────────────────────────────────────

function formatContent(text: string) {
  return text.split('\n').map((line, i, lines) => {
    if (line.startsWith('**') && line.endsWith('**')) {
      return <strong key={i} className="text-cyan-300">{line.slice(2, -2)}</strong>;
    }
    const parts = line.split(/(\*\*[^*]+\*\*)/g);
    return (
      <span key={i}>
        {parts.map((part, j) =>
          part.startsWith('**') && part.endsWith('**')
            ? <strong key={j} className="text-cyan-300">{part.slice(2, -2)}</strong>
            : part
        )}
        {i < lines.length - 1 && <br />}
      </span>
    );
  });
}

interface MessageBubbleProps {
  msg: Message;
  index: number;
  onSpeakMessage?: (text: string) => void;
}

export function MessageBubble({ msg, onSpeakMessage }: MessageBubbleProps) {
  const isUser = msg.role === 'user';
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: 'easeOut' }}
      className={`cs-msg-row ${isUser ? 'cs-msg-row-user' : 'cs-msg-row-bot'}`}
    >
      {!isUser && (
        <div className="cs-bot-avatar">
          <Bot className="w-3.5 h-3.5 text-cyan-400" />
        </div>
      )}
      <div
        className={`cs-bubble ${isUser ? 'cs-bubble-user' : 'cs-bubble-bot'}`}
      >
        {formatContent(msg.content)}
        {msg.quickActions && msg.quickActions.length > 0 && (
          <div className="mt-2.5 flex flex-wrap gap-1.5">
            {msg.quickActions.map((action, idx) =>
              action.type === 'navigate' ? (
                <button
                  key={`${action.label}-${idx}`}
                  onClick={() =>
                    window.dispatchEvent(
                      new CustomEvent('cybersaathi:navigate', {
                        detail: { page: action.target },
                      })
                    )
                  }
                  className="cs-chip cs-chip-action"
                >
                  {action.label}
                  <ChevronRight className="w-3 h-3 ml-0.5" />
                </button>
              ) : (
                <a
                  key={`${action.label}-${idx}`}
                  href={action.type === 'call' ? `tel:${action.target}` : action.target}
                  target={action.target.startsWith('http') ? '_blank' : undefined}
                  rel="noopener noreferrer"
                  className="cs-chip cs-chip-action"
                >
                  {action.label}
                </a>
              )
            )}
          </div>
        )}
        {!isUser && onSpeakMessage && (
          <div className="mt-2.5 pt-1.5 border-t border-slate-700/40 flex items-center justify-between">
            <button
              type="button"
              onClick={() => onSpeakMessage(msg.content)}
              className="text-[11px] text-slate-400 hover:text-cyan-300 transition-colors inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-800/40 hover:bg-slate-700/60"
              title="Listen to this response"
              aria-label="Listen to this response"
            >
              <Volume2 className="w-3 h-3 text-cyan-400" />
              <span>Listen</span>
            </button>
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Typing Indicator ───────────────────────────────────────────────────────

export function TypingIndicator() {
  return (
    <div className="cs-msg-row cs-msg-row-bot">
      <div className="cs-bot-avatar">
        <Bot className="w-3.5 h-3.5 text-cyan-400" />
      </div>
      <div className="cs-bubble cs-bubble-bot cs-typing-bubble">
        <span className="cs-typing-label">Analyzing</span>
        <span className="cs-typing-dot" style={{ animationDelay: '0ms' }} />
        <span className="cs-typing-dot" style={{ animationDelay: '150ms' }} />
        <span className="cs-typing-dot" style={{ animationDelay: '300ms' }} />
      </div>
    </div>
  );
}

// ─── Waveform Display ───────────────────────────────────────────────────────

export function WaveformDisplay() {
  return (
    <div className="flex items-end justify-center gap-[3px] h-5">
      {[0, 1, 2, 3, 4].map((i) => (
        <div
          key={i}
          className="cs-wave-bar"
          style={{ animationDelay: `${i * 120}ms` }}
        />
      ))}
    </div>
  );
}

// ─── Emergency Banner ───────────────────────────────────────────────────────

interface EmergencyBannerProps {
  t: (en: string, hi: string) => string;
}

export function EmergencyBanner({ t }: EmergencyBannerProps) {
  return (
    <div className="px-4 py-2 bg-orange-950/30 border-t border-orange-500/20 flex items-center gap-2 flex-shrink-0">
      <AlertTriangle className="w-3.5 h-3.5 text-orange-400 flex-shrink-0" />
      <p className="text-orange-300/90 text-[11px] font-medium">
        {t('Crisis? Call 1930 or iCall 9152987821', 'संकट? 1930 या iCall 9152987821 पर कॉल करें')}
      </p>
    </div>
  );
}



// ─── Mic Button ─────────────────────────────────────────────────────────────

interface MicButtonProps {
  isListening: boolean;
  voiceSupported: boolean;
  onToggle: () => void;
  t: (en: string, hi: string) => string;
}

export function MicButton({ isListening, voiceSupported, onToggle, t }: MicButtonProps) {
  if (!voiceSupported) return null;

  return (
    <button
      type="button"
      onClick={onToggle}
      className={`cs-mic-btn ${isListening ? 'cs-mic-active' : 'cs-mic-idle'}`}
      aria-label={
        isListening
          ? t('Stop listening', 'सुनना बंद करें')
          : t('Start voice input', 'आवाज़ इनपुट शुरू करें')
      }
      title={
        isListening
          ? t('Tap to stop', 'रोकने के लिए दबाएं')
          : t('Tap to speak', 'बोलने के लिए दबाएं')
      }
    >
      {isListening ? (
        <Square className="w-4 h-4 fill-current" />
      ) : (
        <Mic className="w-4 h-4" />
      )}
      {isListening && <span className="cs-mic-pulse" />}
    </button>
  );
}

// ─── Chat Input Bar (mobile-optimized with auto-growing textarea) ───────────

interface ChatInputProps {
  input: string;
  isListening: boolean;
  isLoading: boolean;
  voiceSupported: boolean;
  onInputChange: (val: string) => void;
  onSend: () => void;
  onToggleMic: () => void;
  t: (en: string, hi: string) => string;
}

export function ChatInput({
  input, isListening, isLoading, voiceSupported,
  onInputChange, onSend, onToggleMic, t,
}: ChatInputProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-resize textarea as content grows (max 4 lines)
  useEffect(() => {
    const el = textareaRef.current;
    if (el) {
      el.style.height = 'auto';
      el.style.height = Math.min(el.scrollHeight, 96) + 'px'; // 96px ≈ 4 lines
    }
  }, [input]);

  return (
    <div className="cs-input-area">
      {/* Listening indicator overlay */}
      <AnimatePresence>
        {isListening && (
          <motion.div
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            className="absolute -top-10 left-0 right-0 flex justify-center pointer-events-none z-10"
          >
            <div className="cs-listening-badge">
              <WaveformDisplay />
              <span className="text-[11px] font-medium ml-1.5">
                {t('Listening — speak now', 'सुन रही हूँ — बोलें')}
              </span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="cs-input-row">
        {/* Auto-growing textarea for mobile-friendly input */}
        <textarea
          ref={textareaRef}
          id="cybersaathi-input"
          value={input}
          onChange={(e) => onInputChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              onSend();
            }
          }}
          placeholder={
            isListening
              ? t('Listening... edit or speak', 'सुन रही हूँ... बोलें या लिखें')
              : t('Ask CyberSaathi anything...', 'CyberSaathi से कुछ भी पूछें...')
          }
          className={`cs-text-input ${isListening ? 'cs-text-input-listening' : ''}`}
          autoComplete="off"
          rows={1}
        />

        {/* Mic button */}
        <MicButton
          isListening={isListening}
          voiceSupported={voiceSupported}
          onToggle={onToggleMic}
          t={t}
        />

        {/* Send button */}
        <button
          type="button"
          onClick={onSend}
          disabled={isLoading || !input.trim()}
          className="cs-send-btn"
          aria-label={t('Send message', 'संदेश भेजें')}
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Send className="w-4 h-4" />
          )}
        </button>
      </div>
    </div>
  );
}

// ─── Error Display (with retry button) ──────────────────────────────────────

interface ErrorDisplayProps {
  error: string;
  onRetry?: () => void;
}

export function ErrorDisplay({ error, onRetry }: ErrorDisplayProps) {
  if (!error) return null;
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      className="cs-error-bar"
    >
      <span className="cs-error-text">{error}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="cs-retry-btn" aria-label="Retry">
          <RefreshCw className="w-3 h-3" />
          <span>Retry</span>
        </button>
      )}
    </motion.div>
  );
}

// ─── Floating Button ────────────────────────────────────────────────────────

interface FloatingButtonProps {
  isEmergency: boolean;
  onClick: () => void;
}

export function FloatingButton({ isEmergency, onClick }: FloatingButtonProps) {
  return (
    <motion.button
      onClick={onClick}
      initial={{ opacity: 0, y: 20, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      whileHover={{ scale: 1.04, y: -2 }}
      whileTap={{ scale: 0.96 }}
      className="cs-fab"
    >
      <div className="cs-fab-glow" />
      <ShieldCheck className="w-5 h-5 relative z-10" />
      <span className="text-sm font-bold relative z-10">CyberSaathi</span>
      {isEmergency && <span className="cs-fab-emergency-dot" />}
    </motion.button>
  );
}
