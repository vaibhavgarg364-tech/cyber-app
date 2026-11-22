import { render, screen } from '@testing-library/react';
import VeyronPro from '../pages/VeyronPro';
import { LanguageProvider } from '../context/LanguageContext';

describe('VeyronPro Component', () => {
  const renderVeyronPro = () => {
    return render(
      <LanguageProvider>
        <VeyronPro />
      </LanguageProvider>
    );
  };

  it('renders all four finalized Pro features with Coming Soon status', () => {
    renderVeyronPro();

    // 4 feature titles
    expect(screen.getByText('CyberSaathi Connect')).toBeInTheDocument();
    expect(screen.getByText('Veyron Web Shield')).toBeInTheDocument();
    expect(screen.getByText('Veyron Identity Watch')).toBeInTheDocument();
    expect(screen.getByText('Veyron Device Guard')).toBeInTheDocument();

    // 4 feature subtitles
    expect(screen.getByText('Live AI Security Calling')).toBeInTheDocument();
    expect(screen.getByText('Proactive Browser Protection')).toBeInTheDocument();
    expect(screen.getByText('Personal Data Exposure Monitoring & Assisted Removal')).toBeInTheDocument();
    expect(screen.getByText('Intelligent Device Security & Threat Monitoring')).toBeInTheDocument();

    // COMING SOON badges - at least 4 in the cards, plus roadmap badge
    const badges = screen.getAllByText('COMING SOON');
    expect(badges.length).toBe(4);
  });

  it('renders planned capabilities for each feature', () => {
    renderVeyronPro();

    // CyberSaathi Connect capabilities
    expect(screen.getByText('Real-time AI voice conversations')).toBeInTheDocument();
    expect(screen.getByText('Interruptible two-way calling')).toBeInTheDocument();

    // Veyron Web Shield capabilities
    expect(screen.getByText('Browser extension protection')).toBeInTheDocument();
    expect(screen.getByText('High-confidence malicious website blocking')).toBeInTheDocument();

    // Veyron Identity Watch capabilities
    expect(screen.getByText('Verified email and identity monitoring')).toBeInTheDocument();
    expect(screen.getByText('Automated removal requests with user authorization')).toBeInTheDocument();

    // Veyron Device Guard capabilities
    expect(screen.getByText('Supported downloaded-file inspection')).toBeInTheDocument();
    expect(screen.getByText('Antivirus and firewall health monitoring')).toBeInTheDocument();
  });

  it('confirms the complete removal of Companion Application Roadmap and Future Enterprise sections', () => {
    renderVeyronPro();

    // Ensure Companion Application Roadmap is gone
    expect(screen.queryByText(/Companion Application Roadmap/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Flutter Architecture/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/shared Flutter codebase/i)).not.toBeInTheDocument();

    // Ensure Future Enterprise Expansion is gone
    expect(screen.queryByText(/Future Enterprise Expansion/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SOC telemetry/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Syslog\/Webhooks/i)).not.toBeInTheDocument();
  });

  it('displays the Citizen Free Protection guarantee and comparison matrix', () => {
    renderVeyronPro();

    expect(screen.getByText(/Core Protection is 100% Free Forever for Every Citizen/i)).toBeInTheDocument();
    expect(screen.getByText('Transparent Capability Comparison')).toBeInTheDocument();
    expect(screen.getByText('Veyron Free (Citizen)')).toBeInTheDocument();
    expect(screen.getByText('Veyron Pro (Personal Suite)')).toBeInTheDocument();
  });
});
