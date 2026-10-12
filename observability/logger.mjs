const SAFE_CODE = /^[A-Za-z0-9_.-]{1,48}$/;

/** Emit allow-listed JSON fields only; never serialize arbitrary errors or requests. */
export function operationalLog(level, event, fields = {}, write = line => {
  (level === 'error' ? console.error : console.log)(line);
}) {
  const record = { timestamp: new Date().toISOString(), level, event };
  for (const key of ['requestId', 'method', 'route', 'status', 'durationMs', 'errorCode', 'component', 'port']) {
    const value = fields[key];
    if (value === undefined || value === null) continue;
    if (key === 'errorCode') record[key] = SAFE_CODE.test(String(value)) ? String(value) : 'UNCLASSIFIED';
    else if (key === 'status' || key === 'durationMs' || key === 'port') {
      if (Number.isFinite(Number(value))) record[key] = Number(value);
    } else if (typeof value === 'string') {
      record[key] = value.slice(0, 80);
    }
  }
  write(JSON.stringify(record));
  return record;
}

export function safeErrorCode(error) {
  const code = error?.code;
  if (typeof code === 'string' && SAFE_CODE.test(code)) return code;
  const status = Number(error?.status);
  return Number.isInteger(status) && status >= 400 && status <= 599 ? `HTTP_${status}` : 'INTERNAL_ERROR';
}
