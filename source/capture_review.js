// Passive observations only: no target requests and no exploit verification.
export function reviewHttpExchange(record) {
  const observations = [];
  const headers = record.response?.headers || {};
  const get = name => { const key = Object.keys(headers).find(k => k.toLowerCase() === name); return key ? headers[key] : undefined; };
  const add = (code, message, evidence) => observations.push({ code, message, evidence, verifiedVulnerability: false });
  if (String(record.url).startsWith('http:')) add('PLAINTEXT_HTTP', '此交换使用明文 HTTP。', { scheme: 'http' });
  const contentType = String(get('content-type') || '');
  if (record.response && contentType.toLowerCase().includes('text/html')) {
    if (!get('content-security-policy')) add('CSP_NOT_OBSERVED', '此 HTML 响应中未观察到 Content-Security-Policy；需结合页面用途评估。', { header: 'content-security-policy' });
    if (!get('x-content-type-options')) add('NOSNIFF_NOT_OBSERVED', '此响应未观察到 X-Content-Type-Options。', { header: 'x-content-type-options' });
  }
  if (String(record.url).startsWith('https:') && record.response && !get('strict-transport-security')) add('HSTS_NOT_OBSERVED', '此 HTTPS 响应未观察到 HSTS；单次响应不证明站点未配置。', { header: 'strict-transport-security' });
  const cookies = get('set-cookie');
  for (const [index, value] of (Array.isArray(cookies) ? cookies : cookies ? [cookies] : []).slice(0, 32).entries()) {
    const attributes = String(value).split(';').slice(1).map(part => part.trim().split('=')[0].toLowerCase());
    for (const attribute of ['secure', 'httponly', 'samesite']) if (!attributes.includes(attribute)) add('COOKIE_ATTRIBUTE_NOT_OBSERVED', `Cookie ${index + 1} 未观察到 ${attribute}；不能仅由此确定可利用性。`, { cookieIndex: index, attribute });
  }
  return { mode: 'passive', networkRequests: 0, exchangeId: record.id, observations, partial: !!record.truncated,
    limitations: ['仅检查已保存的单次 HTTP 元数据；不执行主动扫描，不判定漏洞可利用性。'] };
}
