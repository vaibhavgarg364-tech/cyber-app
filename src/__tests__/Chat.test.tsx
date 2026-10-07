import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CyberSaathi from '../components/CyberSaathi';

jest.mock('../api', () => ({
  chatWithSaathi: jest.fn().mockResolvedValue({ response: 'Backend reply' }),
}));

describe('CyberSaathi chat', () => {
  it('shows intro and language preference prompt', () => {
    render(<CyberSaathi autoOpen />);
    expect(screen.getByText(/Hello! I am CyberSaathi/i)).toBeInTheDocument();
  });

  it('sends message and shows backend response', async () => {
    render(<CyberSaathi autoOpen />);
    const input = screen.getByPlaceholderText(/Ask CyberSaathi anything/i);
    fireEvent.change(input, { target: { value: 'I got a scam call' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    await waitFor(() => {
      expect(screen.getByText(/Backend reply/i)).toBeInTheDocument();
    });
  });
});
