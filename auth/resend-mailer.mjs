const RESEND_ENDPOINT = 'https://api.resend.com/emails';

function mailError(code, status = undefined) {
  const error = new Error('Email delivery was not accepted.');
  error.code = code;
  if (status !== undefined) error.status = status;
  return error;
}

/** Send through Resend and accept only its documented successful response shape. */
export async function sendResendEmail({ apiKey, from, to, subject, text, html, fetchImpl = fetch, timeoutMs = 10_000 }) {
  if (!apiKey || !from) throw mailError('EMAIL_DELIVERY_NOT_CONFIGURED', 503);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await fetchImpl(RESEND_ENDPOINT, {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to: [to], subject, text, html }),
        signal: controller.signal
      });
    } catch (error) {
      throw mailError(controller.signal.aborted ? 'EMAIL_DELIVERY_TIMEOUT' : 'EMAIL_DELIVERY_NETWORK_ERROR');
    }
    if (!response || !Number.isInteger(response.status)) throw mailError('EMAIL_PROVIDER_INVALID_RESPONSE');
    if (!response.ok) throw mailError('EMAIL_PROVIDER_REJECTED', response.status);
    let result;
    try { result = await response.json(); }
    catch { throw mailError('EMAIL_PROVIDER_INVALID_RESPONSE', response.status); }
    if (!result || typeof result.id !== 'string' || !/^re_[A-Za-z0-9]+$/.test(result.id)) {
      throw mailError('EMAIL_PROVIDER_INVALID_RESPONSE', response.status);
    }
    return { accepted: true };
  } finally {
    clearTimeout(timer);
  }
}
