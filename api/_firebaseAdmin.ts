import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  type App,
  applicationDefault,
  cert,
  getApps,
  initializeApp,
  type ServiceAccount,
} from 'firebase-admin/app';
import { type AppCheck, getAppCheck } from 'firebase-admin/app-check';
import { type Auth, type DecodedIdToken, getAuth } from 'firebase-admin/auth';
import { type Firestore, getFirestore, Timestamp } from 'firebase-admin/firestore';

export type ApiRequest = IncomingMessage & {
  body?: unknown;
  query?: Record<string, string | string[] | undefined>;
};

export type AdminRole = 'super_admin' | 'admin' | 'support_admin';

export type RuntimeEnvironment =
  | 'vercel_production'
  | 'vercel_preview'
  | 'ai_studio_preview'
  | 'node_server';

export interface FirebaseAdminContext {
  app: App;
  db: Firestore;
  auth: Auth;
  appCheck: AppCheck;
  projectId: string;
  databaseId: string;
  hasExplicitCert: boolean;
}

export interface VerifiedRequestAuth {
  uid: string;
  email: string;
  emailVerified: boolean;
  adminRole: AdminRole | null;
}

export const BOOTSTRAP_SUPER_ADMIN_EMAILS = new Set([
  'riyajulhasanfahim@gmail.com',
  'mitiu025@gmail.com',
]);

export const DAILY_CHECKIN_BONUS_AD_ID = 'daily_checkin_bonus';
export const DEFAULT_GLOBAL_DAILY_AD_LIMIT = 20;
export const MIN_AD_VIEW_DURATION_SEC = 30;
export const MAX_AD_VIEW_DURATION_SEC = 180;
export const MIN_SECONDS_BETWEEN_COMPLETIONS = 30;

interface ParsedServiceAccount {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

export type ServiceAccountStatus =
  | 'ok'
  | 'missing'
  | 'malformed'
  | 'project_mismatch';

export interface ServiceAccountInspection {
  ok: boolean;
  status: ServiceAccountStatus;
  source: 'service_account_json' | 'split_env_vars' | 'none';
  creds: ParsedServiceAccount | null;
  serviceAccountProjectId: string;
  clientEmailMasked: string;
  error: string;
}

export interface FirebaseAdminDiagnostics {
  environment: RuntimeEnvironment;
  environmentLabel: string;
  targetProjectId: string;
  targetDatabaseId: string;
  bundledProjectId: string;
  bundledDatabaseId: string;
  projectIdConfigured: boolean;
  projectIdMatched: boolean;
  databaseIdConfigured: boolean;
  credentialInspection: ServiceAccountInspection;
  adcAvailable: boolean;
  adminInitialized: boolean;
  initError: string;
  configurationError: string;
}

export function detectRuntimeEnvironment(): RuntimeEnvironment {
  if (process.env.VERCEL_ENV === 'production') {
    return 'vercel_production';
  }
  if (process.env.VERCEL === '1' || Boolean((process.env.VERCEL_ENV || '').trim())) {
    return 'vercel_preview';
  }
  if (Boolean((process.env.K_SERVICE || '').trim())) {
    return 'ai_studio_preview';
  }
  return 'node_server';
}

export function getRuntimeEnvironmentLabel(env: RuntimeEnvironment): string {
  switch (env) {
    case 'vercel_production':
      return 'Vercel Production';
    case 'vercel_preview':
      return 'Vercel Preview';
    case 'ai_studio_preview':
      return 'AI Studio Preview (Cloud Run Sandbox)';
    default:
      return 'Node Server';
  }
}

function maskEmail(email: string): string {
  const clean = email.trim();
  const atIdx = clean.indexOf('@');
  if (atIdx <= 2) return clean ? '***' : '';
  return `${clean.slice(0, 4)}***${clean.slice(atIdx)}`;
}

let cachedBundledConfig: { projectId: string; firestoreDatabaseId: string } | null = null;
export function getBundledFirebaseDefaults(): { projectId: string; firestoreDatabaseId: string } {
  if (cachedBundledConfig) return cachedBundledConfig;

  const candidatePaths: string[] = [path.join(process.cwd(), 'firebase-applet-config.json')];
  try {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    candidatePaths.push(path.resolve(currentDir, '..', 'firebase-applet-config.json'));
    candidatePaths.push(path.resolve(currentDir, 'firebase-applet-config.json'));
  } catch {
    // Fallback to process.cwd() only
  }

  for (const filePath of candidatePaths) {
    try {
      if (!fs.existsSync(filePath)) continue;
      const raw = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const rawProj = String(parsed.projectId || '').trim();
      const rawDb = String(parsed.firestoreDatabaseId || '(default)').trim() || '(default)';
      cachedBundledConfig = {
        projectId: rawProj === 'remixed-project-id' ? '' : rawProj,
        firestoreDatabaseId: rawDb === 'remixed-firestore-database-id' ? '(default)' : rawDb,
      };
      return cachedBundledConfig;
    } catch {
      // Try next candidate path
    }
  }

  cachedBundledConfig = { projectId: '', firestoreDatabaseId: '(default)' };
  return cachedBundledConfig;
}

function isValidProjectOrDbId(value: string): boolean {
  return /^[a-zA-Z0-9._()-]{1,128}$/.test(value);
}

export function resolveTargetFirebase(req: ApiRequest): {
  projectId: string;
  databaseId: string;
} {
  const defaults = getBundledFirebaseDefaults();
  const rawProjHeader = req.headers['x-firebase-project-id'];
  const rawDbHeader = req.headers['x-firestore-database-id'];

  const headerProj = (Array.isArray(rawProjHeader) ? rawProjHeader[0] : rawProjHeader || '').trim();
  const headerDb = (Array.isArray(rawDbHeader) ? rawDbHeader[0] : rawDbHeader || '').trim();

  const envProj = (process.env.FIREBASE_PROJECT_ID || '').trim();
  const envDb = (process.env.FIRESTORE_DATABASE_ID || '').trim();

  const candidateProj = headerProj || envProj || defaults.projectId;
  const candidateDb = headerDb || envDb || defaults.firestoreDatabaseId || '(default)';

  return {
    projectId: isValidProjectOrDbId(candidateProj) ? candidateProj : defaults.projectId,
    databaseId: isValidProjectOrDbId(candidateDb) ? candidateDb : '(default)',
  };
}

function normalizePemPrivateKey(rawKey: string): string {
  return rawKey
    .replace(/\\\\n/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .trim();
}

function stripOuterQuotes(value: string): string {
  const trimmed = value.trim();
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

export function inspectServiceAccountEnv(requestedProjectId?: string): ServiceAccountInspection {
  const cleanRequested = (requestedProjectId || '').trim();
  const rawJson = stripOuterQuotes(process.env.FIREBASE_SERVICE_ACCOUNT_JSON || '');

  if (rawJson) {
    let parsed: Record<string, unknown> | null = null;
    try {
      const decoded = rawJson.startsWith('{')
        ? rawJson
        : Buffer.from(rawJson, 'base64').toString('utf8').trim();
      const candidate = JSON.parse(decoded) as unknown;
      if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
        parsed = candidate as Record<string, unknown>;
      }
    } catch {
      return {
        ok: false,
        status: 'malformed',
        source: 'service_account_json',
        creds: null,
        serviceAccountProjectId: '',
        clientEmailMasked: '',
        error:
          'FIREBASE_SERVICE_ACCOUNT_JSON is malformed (expected valid Service Account JSON object or base64-encoded JSON).',
      };
    }

    if (!parsed) {
      return {
        ok: false,
        status: 'malformed',
        source: 'service_account_json',
        creds: null,
        serviceAccountProjectId: '',
        clientEmailMasked: '',
        error: 'FIREBASE_SERVICE_ACCOUNT_JSON did not parse into a JSON object.',
      };
    }

    const clientEmail = String(parsed.client_email || '').trim();
    const privateKey = normalizePemPrivateKey(String(parsed.private_key || ''));
    const saProjectId = String(parsed.project_id || '').trim();
    const effectiveProjectId = saProjectId || cleanRequested;

    if (!clientEmail || !clientEmail.includes('@')) {
      return {
        ok: false,
        status: 'malformed',
        source: 'service_account_json',
        creds: null,
        serviceAccountProjectId: saProjectId,
        clientEmailMasked: '',
        error: 'FIREBASE_SERVICE_ACCOUNT_JSON is missing a valid "client_email" field.',
      };
    }

    if (
      !privateKey ||
      !privateKey.includes('BEGIN PRIVATE KEY') ||
      !privateKey.includes('END PRIVATE KEY')
    ) {
      return {
        ok: false,
        status: 'malformed',
        source: 'service_account_json',
        creds: null,
        serviceAccountProjectId: saProjectId,
        clientEmailMasked: maskEmail(clientEmail),
        error:
          'FIREBASE_SERVICE_ACCOUNT_JSON is missing a valid PEM "private_key" (BEGIN/END PRIVATE KEY).',
      };
    }

    if (!effectiveProjectId) {
      return {
        ok: false,
        status: 'malformed',
        source: 'service_account_json',
        creds: null,
        serviceAccountProjectId: '',
        clientEmailMasked: maskEmail(clientEmail),
        error: 'FIREBASE_SERVICE_ACCOUNT_JSON is missing "project_id".',
      };
    }

    if (cleanRequested && saProjectId && saProjectId !== cleanRequested) {
      return {
        ok: false,
        status: 'project_mismatch',
        source: 'service_account_json',
        creds: null,
        serviceAccountProjectId: saProjectId,
        clientEmailMasked: maskEmail(clientEmail),
        error: `SERVICE_ACCOUNT_PROJECT_MISMATCH: Service account project_id "${saProjectId}" does not match target Firebase projectId "${cleanRequested}".`,
      };
    }

    return {
      ok: true,
      status: 'ok',
      source: 'service_account_json',
      creds: { projectId: effectiveProjectId, clientEmail, privateKey },
      serviceAccountProjectId: saProjectId || effectiveProjectId,
      clientEmailMasked: maskEmail(clientEmail),
      error: '',
    };
  }

  const clientEmail = stripOuterQuotes(process.env.FIREBASE_CLIENT_EMAIL || '');
  const privateKey = normalizePemPrivateKey(stripOuterQuotes(process.env.FIREBASE_PRIVATE_KEY || ''));
  const defaults = getBundledFirebaseDefaults();
  const envOrRequestedProj = (
    process.env.FIREBASE_PROJECT_ID ||
    cleanRequested ||
    defaults.projectId
  ).trim();

  if (clientEmail || privateKey) {
    if (
      !clientEmail ||
      !clientEmail.includes('@') ||
      !privateKey.includes('BEGIN PRIVATE KEY') ||
      !envOrRequestedProj
    ) {
      return {
        ok: false,
        status: 'malformed',
        source: 'split_env_vars',
        creds: null,
        serviceAccountProjectId: (process.env.FIREBASE_PROJECT_ID || '').trim(),
        clientEmailMasked: maskEmail(clientEmail),
        error:
          'FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY is incomplete or malformed (must include valid email and PEM private key).',
      };
    }
    const explicitEnvProj = (process.env.FIREBASE_PROJECT_ID || '').trim();
    if (cleanRequested && explicitEnvProj && explicitEnvProj !== cleanRequested) {
      return {
        ok: false,
        status: 'project_mismatch',
        source: 'split_env_vars',
        creds: null,
        serviceAccountProjectId: explicitEnvProj,
        clientEmailMasked: maskEmail(clientEmail),
        error: `SERVICE_ACCOUNT_PROJECT_MISMATCH: FIREBASE_PROJECT_ID "${explicitEnvProj}" does not match target Firebase projectId "${cleanRequested}".`,
      };
    }
    return {
      ok: true,
      status: 'ok',
      source: 'split_env_vars',
      creds: { projectId: envOrRequestedProj, clientEmail, privateKey },
      serviceAccountProjectId: envOrRequestedProj,
      clientEmailMasked: maskEmail(clientEmail),
      error: '',
    };
  }

  return {
    ok: false,
    status: 'missing',
    source: 'none',
    creds: null,
    serviceAccountProjectId: '',
    clientEmailMasked: '',
    error: 'FIREBASE_SERVICE_ACCOUNT_JSON environment variable is not set.',
  };
}

export function parseServiceAccountEnv(requestedProjectId?: string): ParsedServiceAccount | null {
  return inspectServiceAccountEnv(requestedProjectId).creds;
}

function hasApplicationDefaultEnvironment(): boolean {
  const env = detectRuntimeEnvironment();
  if (env === 'vercel_production' || env === 'vercel_preview') {
    return false;
  }
  return Boolean(
    (process.env.GOOGLE_APPLICATION_CREDENTIALS || '').trim() ||
      (process.env.K_SERVICE || '').trim() ||
      (process.env.GOOGLE_CLOUD_PROJECT || '').trim() ||
      (process.env.GCLOUD_PROJECT || '').trim(),
  );
}

const contextCache = new Map<string, FirebaseAdminContext>();
const initErrorCache = new Map<string, string>();

export function getFirebaseAdminContext(
  projectId: string,
  databaseId: string,
): FirebaseAdminContext | null {
  const cleanProjectId = projectId.trim();
  if (!cleanProjectId) return null;
  const cleanDbId = (databaseId || '(default)').trim() || '(default)';
  const cacheKey = `${cleanProjectId}::${cleanDbId}`;
  const existing = contextCache.get(cacheKey);
  if (existing) {
    return existing;
  }

  const inspection = inspectServiceAccountEnv(cleanProjectId);
  const saCreds = inspection.creds;
  const canUseAdc = !saCreds && inspection.status === 'missing' && hasApplicationDefaultEnvironment();
  if (!saCreds && !canUseAdc) {
    initErrorCache.set(cacheKey, inspection.error || 'FIREBASE_SERVICE_ACCOUNT_JSON missing.');
    return null;
  }

  try {
    const appName = `adview_admin_${cleanProjectId}`;
    let app: App;
    const existingApp = getApps().find((a) => a.name === appName);
    if (existingApp) {
      app = existingApp;
    } else if (saCreds) {
      const sa: ServiceAccount = {
        projectId: saCreds.projectId,
        clientEmail: saCreds.clientEmail,
        privateKey: saCreds.privateKey,
      };
      app = initializeApp(
        {
          credential: cert(sa),
          projectId: saCreds.projectId,
        },
        appName,
      );
    } else {
      app = initializeApp(
        {
          credential: applicationDefault(),
          projectId: cleanProjectId,
        },
        appName,
      );
    }

    const db =
      cleanDbId && cleanDbId !== '(default)'
        ? getFirestore(app, cleanDbId)
        : getFirestore(app);
    try {
      db.settings({ ignoreUndefinedProperties: true });
    } catch {
      // Firestore instance already initialized in warm container
    }

    const ctx: FirebaseAdminContext = {
      app,
      db,
      auth: getAuth(app),
      appCheck: getAppCheck(app),
      projectId: cleanProjectId,
      databaseId: cleanDbId,
      hasExplicitCert: Boolean(saCreds),
    };
    initErrorCache.delete(cacheKey);
    contextCache.set(cacheKey, ctx);
    return ctx;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Firebase Admin SDK initialization failed.';
    initErrorCache.set(cacheKey, message);
    return null;
  }
}

export function getFirebaseAdminDiagnostics(
  projectId: string,
  databaseId: string,
): { ctx: FirebaseAdminContext | null; diagnostics: FirebaseAdminDiagnostics } {
  const environment = detectRuntimeEnvironment();
  const environmentLabel = getRuntimeEnvironmentLabel(environment);
  const defaults = getBundledFirebaseDefaults();
  const cleanProjectId = projectId.trim();
  const cleanDbId = (databaseId || '(default)').trim() || '(default)';
  const cacheKey = `${cleanProjectId}::${cleanDbId}`;

  const credentialInspection = inspectServiceAccountEnv(cleanProjectId);
  const adcAvailable = hasApplicationDefaultEnvironment();
  const ctx = getFirebaseAdminContext(cleanProjectId, cleanDbId);
  const initError = initErrorCache.get(cacheKey) || '';

  const projectIdConfigured = Boolean(cleanProjectId);
  const projectIdMatched =
    Boolean(cleanProjectId) &&
    (!defaults.projectId || cleanProjectId === defaults.projectId) &&
    (!credentialInspection.serviceAccountProjectId ||
      credentialInspection.serviceAccountProjectId === cleanProjectId);
  const databaseIdConfigured = Boolean(cleanDbId);

  let configurationError = '';
  if (!projectIdConfigured) {
    configurationError =
      'Firebase Project ID is missing in FIREBASE_PROJECT_ID and firebase-applet-config.json.';
  } else if (credentialInspection.status === 'malformed') {
    configurationError = credentialInspection.error;
  } else if (credentialInspection.status === 'project_mismatch') {
    configurationError = credentialInspection.error;
  } else if (defaults.projectId && cleanProjectId !== defaults.projectId) {
    configurationError = `Requested projectId "${cleanProjectId}" does not match bundled Firebase projectId "${defaults.projectId}".`;
  } else if (!credentialInspection.ok) {
    if (environment === 'vercel_production' || environment === 'vercel_preview') {
      configurationError =
        'FIREBASE_SERVICE_ACCOUNT_JSON is not set in Vercel Environment Variables. Add the full Firebase Service Account JSON (for project ' +
        cleanProjectId +
        ') in Vercel Project Settings → Environment Variables and redeploy.';
    } else if (!adcAvailable) {
      configurationError =
        'FIREBASE_SERVICE_ACCOUNT_JSON is not configured and no Application Default Credentials are available.';
    }
  } else if (!ctx && initError) {
    configurationError = initError;
  }

  return {
    ctx,
    diagnostics: {
      environment,
      environmentLabel,
      targetProjectId: cleanProjectId,
      targetDatabaseId: cleanDbId,
      bundledProjectId: defaults.projectId,
      bundledDatabaseId: defaults.firestoreDatabaseId,
      projectIdConfigured,
      projectIdMatched,
      databaseIdConfigured,
      credentialInspection,
      adcAvailable,
      adminInitialized: Boolean(ctx) && !initError,
      initError,
      configurationError,
    },
  };
}

export function isCredentialOrPermissionError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const msg = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: unknown }).code;
  const lower = msg.toLowerCase();
  return (
    code === 7 ||
    code === 'permission-denied' ||
    code === 'PERMISSION_DENIED' ||
    lower.includes('permission_denied') ||
    lower.includes('permission denied') ||
    lower.includes('missing or insufficient permissions') ||
    lower.includes('could not load the default credentials') ||
    lower.includes('unable to detect a project id') ||
    lower.includes('unauthenticated') ||
    lower.includes('invalid_grant')
  );
}

export function applyCors(
  req: ApiRequest,
  res: ServerResponse,
  options: { allowPublicWebhook?: boolean } = {},
): void {
  const originHeader = req.headers.origin;
  const origin = Array.isArray(originHeader) ? originHeader[0] : originHeader || '';
  const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || '';
  const host = Array.isArray(hostHeader) ? hostHeader[0] : hostHeader;

  if (options.allowPublicWebhook) {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Postback-Secret, X-Postback-Signature, X-Postback-Timestamp');
    return;
  }

  if (origin) {
    try {
      const originHost = new URL(origin).host;
      if (host && originHost === host) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
      }
    } catch {
      // Omit ACAO for malformed origins
    }
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Firebase-AppCheck, X-Firebase-Project-Id, X-Firestore-Database-Id',
  );
}

export function sendJson(
  req: ApiRequest,
  res: ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
  options: { allowPublicWebhook?: boolean } = {},
): void {
  applyCors(req, res, options);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

export function sendBackendUnavailable(req: ApiRequest, res: ServerResponse, reason?: string): void {
  const { projectId, databaseId } = resolveTargetFirebase(req);
  const { diagnostics } = getFirebaseAdminDiagnostics(projectId, databaseId);
  const detail = reason || diagnostics.configurationError || diagnostics.credentialInspection.error;
  const errorCode =
    diagnostics.credentialInspection.status === 'malformed'
      ? 'FIREBASE_SERVICE_ACCOUNT_JSON_MALFORMED'
      : diagnostics.credentialInspection.status === 'project_mismatch'
        ? 'SERVICE_ACCOUNT_PROJECT_MISMATCH'
        : 'SERVER_CREDENTIALS_MISSING';

  sendJson(req, res, 503, {
    ok: false,
    status: 'backend_unavailable',
    backendConfigured: false,
    error: errorCode,
    environment: diagnostics.environment,
    targetProjectId: diagnostics.targetProjectId,
    targetDatabaseId: diagnostics.targetDatabaseId,
    credentialStatus: diagnostics.credentialInspection.status,
    ...(detail ? { details: detail, configurationError: detail } : {}),
  });
}

export async function readJsonBody(req: ApiRequest): Promise<Record<string, unknown>> {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body as Record<string, unknown>;
  }
  if (typeof req.body === 'string') {
    try {
      const parsed = JSON.parse(req.body) as unknown;
      return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer | string) => {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) {
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(raw) as unknown;
        resolve(parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {});
      } catch {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

export function getQueryParams(req: ApiRequest): Record<string, unknown> {
  if (req.query && typeof req.query === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(req.query)) {
      out[k] = Array.isArray(v) ? v[0] : v;
    }
    return out;
  }
  const urlStr = req.url || '';
  const qIdx = urlStr.indexOf('?');
  if (qIdx === -1) return {};
  const sp = new URLSearchParams(urlStr.slice(qIdx + 1));
  const out: Record<string, unknown> = {};
  sp.forEach((v, k) => {
    out[k] = v;
  });
  return out;
}

export function getClientIp(req: ApiRequest): string {
  const fwd = req.headers['x-forwarded-for'];
  const raw = Array.isArray(fwd) ? fwd[0] : String(fwd || req.socket?.remoteAddress || 'unknown');
  return raw.split(',')[0].trim().slice(0, 80) || 'unknown';
}

export function hashNetworkIdentifier(req: ApiRequest): string {
  const ip = getClientIp(req);
  const uaHeader = req.headers['user-agent'];
  const ua = Array.isArray(uaHeader) ? uaHeader[0] : String(uaHeader || 'unknown');
  return crypto
    .createHash('sha256')
    .update(`${ip}|${ua.slice(0, 120)}`)
    .digest('hex')
    .slice(0, 24);
}

export function sanitizeId(raw: string): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 120);
  return cleaned || `id_${Date.now()}`;
}

export function normalizeAdDurationSeconds(raw: unknown): number {
  const n = Math.floor(Number(raw));
  if (!Number.isFinite(n) || n < MIN_AD_VIEW_DURATION_SEC || n > MAX_AD_VIEW_DURATION_SEC) {
    return MIN_AD_VIEW_DURATION_SEC;
  }
  return n;
}

export function toMillis(val: unknown): number {
  if (!val) return 0;
  if (typeof val === 'number' && Number.isFinite(val)) return val;
  if (val instanceof Timestamp) return val.toMillis();
  if (val instanceof Date) return val.getTime();
  if (typeof val === 'object') {
    const obj = val as { toMillis?: () => number; seconds?: number; _seconds?: number };
    if (typeof obj.toMillis === 'function') return obj.toMillis();
    const secs = obj.seconds ?? obj._seconds;
    if (typeof secs === 'number' && Number.isFinite(secs)) return secs * 1000;
  }
  return 0;
}

export function getDhakaDateKey(date: Date = new Date()): string {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Dhaka',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date);
}

export function getDhakaYesterdayDateKey(todayDhakaKey: string = getDhakaDateKey()): string {
  const parts = todayDhakaKey.split('-').map((n) => Number(n));
  if (parts.length !== 3 || parts.some((n) => !Number.isFinite(n))) {
    return getDhakaDateKey(new Date(Date.now() - 86_400_000));
  }
  const utcMidnight = Date.UTC(parts[0], parts[1] - 1, parts[2]);
  const prev = new Date(utcMidnight - 86_400_000);
  const yyyy = prev.getUTCFullYear();
  const mm = String(prev.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(prev.getUTCDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

export function timingSafeEqualString(aStr: string, bStr: string): boolean {
  if (!aStr || !bStr) return false;
  const a = Buffer.from(aStr);
  const b = Buffer.from(bStr);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function verifyCallbackSecretOrHmac(
  providedSecret: string,
  providedSignature: string,
  payloadString: string,
  expectedSecret: string,
): boolean {
  if (!expectedSecret) return false;
  if (providedSecret && timingSafeEqualString(providedSecret, expectedSecret)) {
    return true;
  }
  if (providedSignature) {
    const expectedHmac = crypto
      .createHmac('sha256', expectedSecret)
      .update(payloadString)
      .digest('hex');
    if (timingSafeEqualString(providedSignature.toLowerCase(), expectedHmac.toLowerCase())) {
      return true;
    }
  }
  return false;
}

export function verifyAppLixirMd5Signature(params: {
  gameApiKey: string;
  gameId: string;
  userId: string;
  tid: string;
  signature: string;
  secret: string;
}): boolean {
  const sig = params.signature.trim().toLowerCase();
  const secret = params.secret.trim();
  if (!sig || !secret) return false;

  const base = `${params.gameApiKey}${params.gameId}${params.userId}`;
  const candidates: string[] = [];
  if (params.tid) {
    candidates.push(crypto.createHash('md5').update(`${base}${params.tid}${secret}`).digest('hex'));
  }
  candidates.push(crypto.createHash('md5').update(`${base}${secret}`).digest('hex'));

  return candidates.some((expected) => timingSafeEqualString(sig, expected.toLowerCase()));
}

export function isValidAppLixirSiteOrKey(rawValue: string): boolean {
  const clean = rawValue.replace(/^applixir:\/\//i, '').replace(/^applixir:/i, '').trim();
  if (!clean || /^(demo|test|placeholder|0+|none|null|undefined)$/i.test(clean)) {
    return false;
  }
  return /^\d{3,12}$/.test(clean) || /^[a-zA-Z0-9-]{8,64}$/.test(clean);
}

export function getAppLixirBackendEnvStatus(): {
  siteIdConfigured: boolean;
  apiKeyConfigured: boolean;
  secretKeyConfigured: boolean;
} {
  return {
    siteIdConfigured: isValidAppLixirSiteOrKey((process.env.APPLIXIR_SITE_ID || '').trim()),
    apiKeyConfigured: Boolean((process.env.APPLIXIR_API_KEY || '').trim()),
    secretKeyConfigured: Boolean((process.env.APPLIXIR_SECRET_KEY || '').trim()),
  };
}

const ROLE_WEIGHT: Record<AdminRole, number> = {
  support_admin: 1,
  admin: 2,
  super_admin: 3,
};

export function hasMinimumRole(actual: AdminRole | null, required: AdminRole): boolean {
  if (!actual) return false;
  return ROLE_WEIGHT[actual] >= ROLE_WEIGHT[required];
}

export async function verifyAuthAndRoleAdmin(
  req: ApiRequest,
  ctx: FirebaseAdminContext,
  options: {
    requireVerifiedEmail?: boolean;
    requiredAdminRole?: AdminRole;
  } = {},
): Promise<{ auth?: VerifiedRequestAuth; status?: number; error?: string }> {
  if (process.env.ENFORCE_APP_CHECK === 'true') {
    const rawAc = req.headers['x-firebase-appcheck'];
    const acToken = Array.isArray(rawAc) ? rawAc[0] : String(rawAc || '').trim();
    if (!acToken) {
      return { status: 401, error: 'Missing Firebase App Check token' };
    }
    try {
      await ctx.appCheck.verifyToken(acToken);
    } catch {
      return { status: 401, error: 'Invalid Firebase App Check token' };
    }
  }

  const authHeader = String(req.headers.authorization || '');
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return { status: 401, error: 'Missing Authorization Bearer token' };
  }

  let decoded: DecodedIdToken;
  try {
    decoded = await ctx.auth.verifyIdToken(match[1].trim(), ctx.hasExplicitCert);
  } catch (err) {
    if (!ctx.hasExplicitCert && isCredentialOrPermissionError(err)) {
      try {
        decoded = await ctx.auth.verifyIdToken(match[1].trim(), false);
      } catch {
        return { status: 401, error: 'Invalid or expired auth token' };
      }
    } else {
      return { status: 401, error: 'Invalid or expired auth token' };
    }
  }

  const email = String(decoded.email || '');
  const emailVerified = Boolean(decoded.email_verified);

  if (options.requireVerifiedEmail !== false && !emailVerified) {
    return { status: 403, error: 'Verified email required' };
  }

  let resolvedRole: AdminRole | null = null;
  if (BOOTSTRAP_SUPER_ADMIN_EMAILS.has(email.toLowerCase()) && emailVerified) {
    resolvedRole = 'super_admin';
  }

  const claimRole = (decoded as Record<string, unknown>).adminRole;
  if (
    !resolvedRole &&
    emailVerified &&
    (claimRole === 'super_admin' || claimRole === 'admin' || claimRole === 'support_admin')
  ) {
    resolvedRole = claimRole;
  }

  if (!resolvedRole && options.requiredAdminRole) {
    try {
      const marker = await ctx.db.collection('admins').doc(decoded.uid).get();
      if (marker.exists) {
        const docRole = marker.data()?.role;
        if (docRole === 'super_admin' || docRole === 'admin' || docRole === 'support_admin') {
          resolvedRole = docRole;
        } else {
          resolvedRole = 'admin';
        }
      }
    } catch {
      // Propagate permission check below
    }
  }

  if (options.requiredAdminRole && !hasMinimumRole(resolvedRole, options.requiredAdminRole)) {
    return { status: 403, error: `Requires ${options.requiredAdminRole} privileges` };
  }

  return {
    auth: {
      uid: decoded.uid,
      email,
      emailVerified,
      adminRole: resolvedRole,
    },
  };
}
