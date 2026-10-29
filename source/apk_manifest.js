// AndroidManifest.xml reader on top of the AXML decoder: identity, SDK levels, permissions, application flags and every
// component with its EFFECTIVE exposure (the explicit android:exported value, or the platform default when absent).
// Reading is tolerant, like Android: odd values become anomalies rather than errors, because a manifest that confuses
// tools while the platform accepts it is itself a finding.
import { attribute, parseAxml } from './apk_axml.js';

export const MANIFEST_LIMITS = Object.freeze({ components: 5000, filters: 64, permissions: 2000, metaData: 200, text: 512 });
const COMPONENT_KINDS = new Map([['activity', 'activity'], ['activity-alias', 'activity'], ['service', 'service'], ['receiver', 'receiver'], ['provider', 'provider']]);
const clip = (text, limit) => (typeof text === 'string' && text.length > limit ? text.slice(0, limit) : text);

function valueOf(element, name, limits) {
  const found = attribute(element, name);
  if (!found) return { present: false, value: null };
  return { present: true, value: found.type === 'string' || found.type === 'null' ? clip(found.text, limits.text) : found.value, type: found.type };
}
const bool = (element, name, limits) => { const v = valueOf(element, name, limits); return v.present && typeof v.value === 'boolean' ? v.value : v.present ? undefined : null; };
const integer = (element, name, limits) => { const v = valueOf(element, name, limits); return v.present && typeof v.value === 'number' ? v.value : null; };
const text = (element, name, limits) => { const v = valueOf(element, name, limits); return v.present && typeof v.value === 'string' ? v.value : null; };

/** Absolute class name for a component name written relative to the package (".Main", "Main", or fully qualified). */
export function qualify(name, packageName) {
  if (!name) return null;
  if (name.startsWith('.')) return (packageName ?? '') + name;
  return name.includes('.') || !packageName ? name : `${packageName}.${name}`;
}

function intentFilter(element, limits) {
  const out = { actions: [], categories: [], data: [], priority: integer(element, 'priority', limits) };
  for (const child of element.children) {
    if (child.name === 'action') { const n = text(child, 'name', limits); if (n) out.actions.push(n); }
    else if (child.name === 'category') { const n = text(child, 'name', limits); if (n) out.categories.push(n); }
    else if (child.name === 'data' && out.data.length < 32) {
      const d = {}; for (const key of ['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']) { const v = text(child, key, limits); if (v !== null) d[key] = v; }
      out.data.push(d);
    }
  }
  return out;
}

/** Parse a manifest from its binary XML bytes. */
export function parseManifest(buffer, options = {}) {
  const limits = { ...MANIFEST_LIMITS, ...options };
  const axml = parseAxml(buffer, options.axml);
  const anomalies = axml.anomalies.map(a => ({ source: 'axml', ...a })), note = (code, detail = {}) => { if (anomalies.length < 128) anomalies.push({ source: 'manifest', code, ...detail }); };
  const root = axml.root;
  if (root.name !== 'manifest') note('root-not-manifest', { name: root.name.slice(0, 64) });
  const packageName = text(root, 'package', limits);
  if (!packageName) note('missing-package'); else if (!/^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$/.test(packageName)) note('unusual-package-name', { package: packageName.slice(0, 128) });
  const children = name => root.children.filter(c => c.name === name);
  const sdkElement = children('uses-sdk')[0];
  const sdk = { min: sdkElement ? integer(sdkElement, 'minSdkVersion', limits) : null, target: sdkElement ? integer(sdkElement, 'targetSdkVersion', limits) : null, max: sdkElement ? integer(sdkElement, 'maxSdkVersion', limits) : null };
  if (!sdkElement) note('missing-uses-sdk');
  const effectiveTarget = sdk.target ?? sdk.min ?? 1;

  const permissions = [], seenPermission = new Set();
  for (const tag of ['uses-permission', 'uses-permission-sdk-23', 'uses-permission-sdk-m']) {
    for (const element of children(tag)) {
      const name = text(element, 'name', limits);
      if (!name) { note('permission-without-name', { tag }); continue; }
      if (permissions.length >= limits.permissions) { note('permission-limit', { limit: limits.permissions }); break; }
      if (seenPermission.has(name)) note('duplicate-permission', { name: name.slice(0, 128) });
      seenPermission.add(name); permissions.push({ name, tag, maxSdk: integer(element, 'maxSdkVersion', limits) });
    }
  }
  const declaredPermissions = children('permission').map(e => ({ name: text(e, 'name', limits), protectionLevel: valueOf(e, 'protectionLevel', limits).value })).filter(p => p.name).slice(0, 200);

  const application = children('application')[0] ?? null;
  if (!application) note('missing-application');
  const app = application && {
    name: qualify(text(application, 'name', limits), packageName), label: valueOf(application, 'label', limits).value, process: text(application, 'process', limits),
    debuggable: bool(application, 'debuggable', limits), allowBackup: bool(application, 'allowBackup', limits), testOnly: bool(root, 'testOnly', limits) ?? bool(application, 'testOnly', limits),
    persistent: bool(application, 'persistent', limits), usesCleartextTraffic: bool(application, 'usesCleartextTraffic', limits), hasCode: bool(application, 'hasCode', limits),
    networkSecurityConfig: valueOf(application, 'networkSecurityConfig', limits).value, appComponentFactory: text(application, 'appComponentFactory', limits),
  };

  const components = [], names = new Set(), metaData = [];
  for (const child of application ? application.children : []) {
    if (child.name === 'meta-data') { if (metaData.length < limits.metaData) metaData.push({ name: text(child, 'name', limits), value: valueOf(child, 'value', limits).value ?? valueOf(child, 'resource', limits).value }); continue; }
    const kind = COMPONENT_KINDS.get(child.name);
    if (!kind) continue;
    if (components.length >= limits.components) { note('component-limit', { limit: limits.components }); break; }
    const raw = text(child, 'name', limits), name = qualify(raw, packageName);
    if (!raw) note('component-without-name', { kind: child.name });
    const filters = child.children.filter(c => c.name === 'intent-filter');
    if (filters.length > limits.filters) note('many-intent-filters', { name, count: filters.length });
    const parsedFilters = filters.slice(0, limits.filters).map(f => intentFilter(f, limits)), explicit = bool(child, 'exported', limits);
    let exported;
    if (explicit === true || explicit === false) exported = explicit;
    else if (kind === 'provider') exported = effectiveTarget < 17;
    else { exported = parsedFilters.length > 0; if (exported && effectiveTarget >= 31) note('exported-missing-with-filter', { name, targetSdk: effectiveTarget }); }
    const label = `${child.name}:${name}`;
    if (name && names.has(label)) note('duplicate-component', { name }); names.add(label);
    components.push({ kind, tag: child.name, name, exported, exportedExplicit: explicit === true || explicit === false, enabled: bool(child, 'enabled', limits) !== false, permission: text(child, 'permission', limits),
      process: text(child, 'process', limits), targetActivity: child.name === 'activity-alias' ? qualify(text(child, 'targetActivity', limits), packageName) : undefined,
      authorities: kind === 'provider' ? text(child, 'authorities', limits) : undefined, grantUriPermissions: kind === 'provider' ? bool(child, 'grantUriPermissions', limits) : undefined,
      launcher: parsedFilters.some(f => f.actions.includes('android.intent.action.MAIN') && f.categories.includes('android.intent.category.LAUNCHER')), intentFilters: parsedFilters,
      priority: Math.max(0, ...parsedFilters.map(f => f.priority ?? 0)) });
  }
  const launchers = components.filter(c => c.launcher);
  if (application && !launchers.length) note('no-launcher-activity');
  for (const c of launchers) if (!c.enabled) note('disabled-launcher', { name: c.name });
  const highPriority = components.filter(c => c.priority >= 1000);
  if (highPriority.length) note('high-priority-filter', { count: highPriority.length, first: highPriority[0].name });

  return {
    package: packageName, versionCode: integer(root, 'versionCode', limits), versionName: text(root, 'versionName', limits), sharedUserId: text(root, 'sharedUserId', limits),
    installLocation: valueOf(root, 'installLocation', limits).value, sdk, permissions, declaredPermissions, application: app, components, metaData,
    features: children('uses-feature').map(e => ({ name: text(e, 'name', limits), required: bool(e, 'required', limits) })).filter(f => f.name).slice(0, 100),
    libraries: children('uses-library').concat(application ? application.children.filter(c => c.name === 'uses-library') : []).map(e => text(e, 'name', limits)).filter(Boolean).slice(0, 100),
    elements: axml.elements, strings: axml.strings, utf8Pool: axml.utf8Pool, anomalies,
  };
}
