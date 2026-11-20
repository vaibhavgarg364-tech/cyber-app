/* eslint-disable @typescript-eslint/no-explicit-any -- api.js returns dynamic backend JSON */
export function chatWithSaathi(
  message: string,
  history?: Array<{ role: string; content: string }>,
  language?: string,
): Promise<any>;

export function checkEmail(email: string): Promise<any>;

export function scanLink(url: string): Promise<any>;

export function checkApp(appName: string, packageName?: string): Promise<any>;

export function detectDeepfake(fileOrUrl: File | string | null): Promise<any>;

export function getHelplines(incidentType: string, userState: string): Promise<any>;

export function getCyberCell(params?: {
  state?: string;
  lat?: number;
  lng?: number;
  isGps?: boolean;
}): Promise<any>;

export function generateComplaintDraft(params?: {
  incidentDesc?: string;
  incidentType?: string;
  userState?: string;
}): Promise<any>;
