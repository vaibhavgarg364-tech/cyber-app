import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import CyberSaathi from '../components/CyberSaathi';
import { chatWithSaathi } from '../api';

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

  it('renders Listen button on assistant message and allows replaying', async () => {
    render(<CyberSaathi autoOpen />);
    const listenButtons = screen.getAllByRole('button', { name: /Listen to this response/i });
    expect(listenButtons.length).toBeGreaterThanOrEqual(1);
    fireEvent.click(listenButtons[0]);
    // Verifies button click does not throw
  });

  it('prevents duplicate submissions on rapid enter presses', async () => {
    const chatMock = chatWithSaathi as unknown as jest.Mock;
    chatMock.mockClear();

    render(<CyberSaathi autoOpen />);
    const input = screen.getByPlaceholderText(/Ask CyberSaathi anything/i);
    fireEvent.change(input, { target: { value: 'Single request check' } });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });

    await waitFor(() => {
      expect(chatMock).toHaveBeenCalledTimes(1);
    });
  });
});
