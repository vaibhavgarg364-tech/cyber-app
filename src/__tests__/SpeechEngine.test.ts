import {
  detectSpeechLanguage,
  getBestVoice,
  cleanTextForSpeech,
  splitIntoSentences,
} from '../components/useSpeechEngine';

describe('SpeechEngine utilities', () => {
  describe('detectSpeechLanguage', () => {
    it('detects Hindi for Devanagari text', () => {
      const hindi = 'नमस्ते, मैं साइबर साथी हूँ। आपकी क्या मदद कर सकती हूँ?';
      expect(detectSpeechLanguage(hindi)).toBe('hi-IN');
    });

    it('detects English for standard English text', () => {
      const en = "Hello, I'm CyberSaathi, your digital safety assistant. How can I help you today?";
      expect(detectSpeechLanguage(en)).toBe('en-IN');
    });

    it('detects en-IN for Hinglish text in Latin script', () => {
      const hinglish = 'Aap bilkul sahi jagah aaye hain. Main aapko suspicious links aur online fraud samajhne mein help kar sakti hoon.';
      expect(detectSpeechLanguage(hinglish)).toBe('en-IN');
    });

    it('defaults to en-IN for empty or non-Devanagari text', () => {
      expect(detectSpeechLanguage('')).toBe('en-IN');
      expect(detectSpeechLanguage('1930')).toBe('en-IN');
    });
  });

  describe('getBestVoice', () => {
    const mockVoices = [
      { name: 'Microsoft David Desktop - English (United States)', lang: 'en-US' },
      { name: 'Microsoft Ravi - English (India)', lang: 'en-IN' },
      { name: 'Microsoft Heera - English (India)', lang: 'en-IN' },
      { name: 'Microsoft Neerja Online (Natural) - English (India)', lang: 'en-IN' },
      { name: 'Microsoft Swara Online (Natural) - Hindi (India)', lang: 'hi-IN' },
      { name: 'Microsoft Madhur Online (Natural) - Hindi (India)', lang: 'hi-IN' },
      { name: 'Microsoft Hemant - Hindi (India)', lang: 'hi-IN' },
      { name: 'Google हिन्दी', lang: 'hi-IN' },
      { name: 'Microsoft Zira Desktop - English (United States)', lang: 'en-US' },
    ] as unknown as SpeechSynthesisVoice[];

    it('selects Microsoft Neerja Online (Natural) as primary female voice for English (India)', () => {
      const best = getBestVoice(mockVoices, 'en-IN');
      expect(best).not.toBeNull();
      expect(best?.name).toBe('Microsoft Neerja Online (Natural) - English (India)');
    });

    it('selects Microsoft Swara Online (Natural) as primary female voice for Hindi', () => {
      const best = getBestVoice(mockVoices, 'hi-IN');
      expect(best).not.toBeNull();
      expect(best?.name).toBe('Microsoft Swara Online (Natural) - Hindi (India)');
    });

    it('strictly avoids male voices even if they match the language exactly', () => {
      const maleOnlyVoices = [
        { name: 'Microsoft Ravi - English (India)', lang: 'en-IN' },
        { name: 'Microsoft Rishi - English (India)', lang: 'en-IN' },
        { name: 'Microsoft David Desktop - English (United States)', lang: 'en-US' },
      ] as unknown as SpeechSynthesisVoice[];

      const hindiMaleVoices = [
        { name: 'Microsoft Madhur Online (Natural) - Hindi (India)', lang: 'hi-IN' },
        { name: 'Microsoft Hemant - Hindi (India)', lang: 'hi-IN' },
      ] as unknown as SpeechSynthesisVoice[];

      // Even if fallback selects something, the score should heavily penalize male voices
      const voice = getBestVoice(mockVoices, 'en-IN');
      expect(voice?.name).not.toContain('Ravi');
      expect(voice?.name).not.toContain('David');

      const hiVoice = getBestVoice(mockVoices, 'hi-IN');
      expect(hiVoice?.name).not.toContain('Madhur');
      expect(hiVoice?.name).not.toContain('Hemant');

      // Check with male-only arrays
      expect(getBestVoice(maleOnlyVoices, 'en-IN')).toBeDefined();
      expect(getBestVoice(hindiMaleVoices, 'hi-IN')).toBeDefined();
    });

    it('selects offline female voice when online voices are absent', () => {
      const offlineVoices = [
        { name: 'Microsoft David Desktop - English (United States)', lang: 'en-US' },
        { name: 'Microsoft Zira Desktop - English (United States)', lang: 'en-US' },
      ] as unknown as SpeechSynthesisVoice[];

      const best = getBestVoice(offlineVoices, 'en-US');
      expect(best?.name).toContain('Zira');
    });
  });

  describe('cleanTextForSpeech', () => {
    it('strips markdown bold, italics, headers, code, and links', () => {
      const raw = '### Emergency Alert\n**Important**: Please check `https://scam.example.com` or [Portal](https://safe.gov.in) immediately.';
      const cleaned = cleanTextForSpeech(raw);
      expect(cleaned).not.toContain('###');
      expect(cleaned).not.toContain('**');
      expect(cleaned).not.toContain('`');
      expect(cleaned).not.toContain('https://');
      expect(cleaned).toContain('Important, Please check or Portal immediately.');
    });

    it('phonetically expands cybersecurity and Indian helpline terms', () => {
      const raw = 'Contact 1930 and visit cybercrime.gov.in. Do not share your OTP or UPI PIN.';
      const cleaned = cleanTextForSpeech(raw);
      expect(cleaned).toContain('one nine three zero');
      expect(cleaned).toContain('cybercrime dot gov dot in');
      expect(cleaned).toContain('O T P');
      expect(cleaned).toContain('U P I');
    });

    it('strips emoji sequences cleanly', () => {
      const raw = 'Stay alert! 🚨🛡️ Never share financial credentials. ⚠️';
      const cleaned = cleanTextForSpeech(raw);
      expect(cleaned).not.toContain('🚨');
      expect(cleaned).not.toContain('🛡️');
      expect(cleaned).not.toContain('⚠️');
      expect(cleaned).toBe('Stay alert! Never share financial credentials.');
    });

    it('formats pauses for Hindi Purna Viram', () => {
      const raw = 'घबराएं नहीं। अपने बैंक को सूचित करें।';
      const cleaned = cleanTextForSpeech(raw);
      expect(cleaned).toContain('। ');
    });
  });

  describe('splitIntoSentences', () => {
    it('returns short text as single chunk', () => {
      const text = 'Hello, how can I assist you with digital security today?';
      const chunks = splitIntoSentences(text);
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).toBe(text);
    });

    it('splits long paragraph at sentence boundaries', () => {
      const longText = 'If you notice unauthorized transactions, act immediately. Contact your bank to freeze your account. Next, call the national cybercrime helpline at 1930. Finally, file an official cyber complaint online at cybercrime dot gov dot in so the authorities can track the digital money trail.';
      const chunks = splitIntoSentences(longText);
      expect(chunks.length).toBeGreaterThanOrEqual(1);
      for (const chunk of chunks) {
        expect(chunk.length).toBeLessThanOrEqual(260);
      }
    });
  });

  describe('Deterministic Voice Selection Stability', () => {
    const mockVoices = [
      { name: 'Microsoft David Desktop - English (United States)', lang: 'en-US' },
      { name: 'Microsoft Ravi - English (India)', lang: 'en-IN' },
      { name: 'Microsoft Heera - English (India)', lang: 'en-IN' },
      { name: 'Microsoft Neerja Online (Natural) - English (India)', lang: 'en-IN' },
      { name: 'Microsoft Swara Online (Natural) - Hindi (India)', lang: 'hi-IN' },
      { name: 'Microsoft Madhur Online (Natural) - Hindi (India)', lang: 'hi-IN' },
      { name: 'Microsoft Zira Desktop - English (United States)', lang: 'en-US' },
    ] as unknown as SpeechSynthesisVoice[];

    it('returns the exact same voice on multiple sequential calls (stable determinism)', () => {
      const voice1 = getBestVoice(mockVoices, 'en-IN');
      const voice2 = getBestVoice(mockVoices, 'en-IN');
      expect(voice1).toBe(voice2);
      expect(voice1?.name).toBe('Microsoft Neerja Online (Natural) - English (India)');

      const hiVoice1 = getBestVoice(mockVoices, 'hi-IN');
      const hiVoice2 = getBestVoice(mockVoices, 'hi-IN');
      expect(hiVoice1).toBe(hiVoice2);
      expect(hiVoice1?.name).toBe('Microsoft Swara Online (Natural) - Hindi (India)');
    });

    it('falls back gracefully to offline female voice when online voices are missing', () => {
      const offlineOnly = [
        { name: 'Microsoft David Desktop - English (United States)', lang: 'en-US' },
        { name: 'Microsoft Zira Desktop - English (United States)', lang: 'en-US' },
      ] as unknown as SpeechSynthesisVoice[];

      const voice = getBestVoice(offlineOnly, 'en-US');
      expect(voice?.name).toBe('Microsoft Zira Desktop - English (United States)');
    });
  });
});
