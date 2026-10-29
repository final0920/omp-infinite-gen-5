// Keep the failure reason while hiding runtime install paths and engine versions.
export function publicEngineError(error, cfg) {
  let message = String(error?.message ?? error);
  for (const configuredPath of [cfg?.pythonExe, cfg?.idaDir]) {
    if (!configuredPath || !/[\\/]/.test(configuredPath)) continue;
    const variants = new Set([
      configuredPath,
      configuredPath.replace(/\\/g, '/'),
      configuredPath.replace(/\//g, '\\'),
      configuredPath.replace(/\\/g, '\\\\'),
    ]);
    for (const variant of variants) {
      const escaped = variant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      message = message.replace(new RegExp(escaped, 'gi'), '[Reverse runtime]');
    }
  }
  return message
    .replace(/\b(?:IDA(?:\s+(?:Professional|Pro))?|idalib|idapro|Hex[- ]?Rays)(?:\s+(?:SDK|Decompiler))?\s*(?:v(?:ersion)?[ .:=]*)?(?:\d+(?:\.[\dx]+)*(?:[a-z][\w.-]*)?|\(\s*\d+\s*(?:,\s*\d+\s*)+\))/gi, 'Reverse')
    .replace(/\b(?:IDA(?:\s+(?:Professional|Pro))?|idalib|idapro|Hex[- ]?Rays)\b/gi, 'Reverse');
}
