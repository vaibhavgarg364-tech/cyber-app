import React from 'react';
import { fireEvent, render, screen, waitFor, act } from '@testing-library/react';
import QRShield from '../pages/QRShield';
import { scanQR } from '../api';

jest.mock('../api', () => ({
  scanQR: jest.fn(),
  scanQRPayload: jest.fn(),
  recordUserActivity: jest.fn(),
}));

// Mock framer-motion to render children directly
jest.mock('framer-motion', () => ({
  motion: {
    div: ({ children, className, ...props }: React.HTMLAttributes<HTMLDivElement>) => (
      <div className={className} {...props}>
        {children}
      </div>
    ),
  },
  AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe('QR Shield Camera Viewfinder & Controls', () => {
  let mockStream: MediaStream;
  let mockTrackStop: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    mockTrackStop = jest.fn();
    mockStream = {
      getTracks: jest.fn().mockReturnValue([
        { stop: mockTrackStop, kind: 'video' },
      ]),
    } as unknown as MediaStream;

    // Mock HTMLMediaElement & HTMLVideoElement methods and dimensions
    window.HTMLMediaElement.prototype.play = jest.fn().mockResolvedValue(undefined);
    window.HTMLMediaElement.prototype.pause = jest.fn();
    Object.defineProperty(HTMLVideoElement.prototype, 'videoWidth', { get: () => 640, configurable: true });
    Object.defineProperty(HTMLVideoElement.prototype, 'videoHeight', { get: () => 480, configurable: true });
    Object.defineProperty(HTMLVideoElement.prototype, 'readyState', { get: () => 4, configurable: true });

    // Mock HTMLCanvasElement for Jest jsdom
    HTMLCanvasElement.prototype.getContext = jest.fn().mockReturnValue({
      drawImage: jest.fn(),
    }) as unknown as typeof HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.toBlob = jest.fn((callback: BlobCallback) => {
      callback(new Blob(['fake-image-bytes'], { type: 'image/jpeg' }));
    });

    // Mock navigator.mediaDevices
    Object.defineProperty(navigator, 'mediaDevices', {
      writable: true,
      value: {
        getUserMedia: jest.fn().mockResolvedValue(mockStream),
        enumerateDevices: jest.fn().mockResolvedValue([
          { deviceId: 'cam1', kind: 'videoinput', label: 'Front Camera' },
        ]),
      },
    });
  });

  it('renders camera tab with starter card and persistent video element', async () => {
    render(<QRShield />);

    // Click Camera Scanner tab
    const cameraTabBtn = screen.getByText(/Camera Scanner/i);
    fireEvent.click(cameraTabBtn);

    // Starter card elements should be visible
    expect(screen.getByText(/Live Camera QR Scanner/i)).toBeInTheDocument();
    expect(screen.getByText(/Open Camera Viewfinder/i)).toBeInTheDocument();

    // Video element must exist in DOM even when inactive
    const video = document.querySelector('video');
    expect(video).toBeInTheDocument();
    expect(video).toHaveAttribute('playsinline');
    expect(video?.muted).toBe(true);
  });

  it('starts camera stream, reveals viewfinder and displays capture controls', async () => {
    render(<QRShield />);

    // Switch to Camera Scanner tab
    fireEvent.click(screen.getByText(/Camera Scanner/i));

    const startBtn = screen.getByText(/Open Camera Viewfinder/i);
    await act(async () => {
      fireEvent.click(startBtn);
    });

    // Verify getUserMedia was called
    await waitFor(() => {
      expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalled();
    });

    // Viewfinder controls should now be visible
    await waitFor(() => {
      expect(screen.getByText(/Capture & Scan QR/i)).toBeInTheDocument();
      expect(screen.getByText(/Auto-Scan: ON/i)).toBeInTheDocument();
      expect(screen.getByText(/Stop/i)).toBeInTheDocument();
    });

    // Auto-scan toggle can be switched off/on
    const autoScanBtn = screen.getByText(/Auto-Scan: ON/i);
    fireEvent.click(autoScanBtn);
    expect(screen.getByText(/Auto-Scan: OFF/i)).toBeInTheDocument();

    // Stop button stops stream and returns to starter screen
    const stopBtn = screen.getByText(/Stop/i);
    fireEvent.click(stopBtn);
    expect(mockTrackStop).toHaveBeenCalled();

    await waitFor(() => {
      expect(screen.getByText(/Open Camera Viewfinder/i)).toBeInTheDocument();
    });
  });

  it('handles camera permission denial gracefully with retry option', async () => {
    const permError = new Error('Permission denied');
    permError.name = 'NotAllowedError';
    (navigator.mediaDevices.getUserMedia as jest.Mock).mockRejectedValueOnce(permError);

    render(<QRShield />);
    fireEvent.click(screen.getByText(/Camera Scanner/i));

    const startBtn = screen.getByText(/Open Camera Viewfinder/i);
    await act(async () => {
      fireEvent.click(startBtn);
    });

    await waitFor(() => {
      expect(screen.getByText(/Camera permission denied/i)).toBeInTheDocument();
      expect(screen.getByText(/Retry Camera Access/i)).toBeInTheDocument();
    });
  });

  it('captures frame manually and renders security report on detection', async () => {
    (scanQR as jest.Mock).mockResolvedValueOnce({
      verdict: 'SAFE',
      risk_score: 10,
      classification: 'URL',
      title: 'Legitimate Portal',
      raw_payload: 'https://example.com/login',
      payload_type: 'url',
      qr_type: 'URL',
      findings: [],
      timestamp: '2026-11-21T10:00:00Z',
    });

    render(<QRShield />);
    fireEvent.click(screen.getByText(/Camera Scanner/i));

    await act(async () => {
      fireEvent.click(screen.getByText(/Open Camera Viewfinder/i));
    });

    await waitFor(() => {
      expect(screen.getByText(/Capture & Scan QR/i)).toBeInTheDocument();
    });

    const captureBtn = screen.getByText(/Capture & Scan QR/i);
    await act(async () => {
      fireEvent.click(captureBtn);
    });

    await waitFor(() => {
      expect(screen.getByText(/NO KNOWN THREAT DETECTED/i)).toBeInTheDocument();
      expect(screen.getByText(/https:\/\/example.com\/login/i)).toBeInTheDocument();
    });
  });
});
