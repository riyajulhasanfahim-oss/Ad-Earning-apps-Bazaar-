import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { IncomingMessage, ServerResponse } from 'node:http';

export type ApiRequest = IncomingMessage & {
  body?: unknown;
  query?: Record<string, string | string[] | undefined>;
};

export interface ServiceAccountCreds {
  projectId: string;
  clientEmail: string;
  privateKey: string;
}

export interface FirestoreRestContext {
  projectId: string;
  databaseId: string;
  accessToken: string;
}

export interface VerifiedIdToken {
  uid: string;
  email: string;
  emailVerified: boolean;
}

export const DAILY_CHECKIN_BONUS_AD_ID = 'daily_checkin_bonus';
export const DEFAULT_GLOBAL_DAILY_AD_LIMIT = 20;
export const MIN_AD_VIEW_DURATION_SEC = 30;
export const MAX_AD_VIEW_DURATION_SEC = 180;
export const MIN_SECONDS_BETWEEN_COMPLETIONS = 30;

let cachedBundledConfig: { projectId: string; firestoreDatabaseId: string } | null = null;
function getBundledFirebaseDefaults(): { projectId: string; firestoreDatabaseId: string } {
  if (cachedBundledConfig) return cachedBundledConfig;
  try {
    const raw = fs.readFileSync(path.join(process.cwd(), 'firebase-applet-config.json'), 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    cachedBundledConfig = {
      projectId: String(parsed.projectId || '').trim(),
      firestoreDatabaseId: String(parsed.firestoreDatabaseId || '(default)').trim() || '(default)',
    };
    return cachedBundledConfig;
  } catch {
    cachedBundledConfig = { projectId: '', firestoreDatabaseId: '(default)' };
    return cachedBundledConfig;
  }
}

export function applyCors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Firebase-AppCheck, X-Firebase-Project-Id, X-Firestore-Database-Id',
  );
}

export function sendJson(
  res: ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
): void {
  applyCors(res);
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
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

export function getServiceAccountCreds(requestedProjectId?: string): ServiceAccountCreds | null {
  const rawJson = (process.env.FIREBASE_SERVICE_ACCOUNT_JSON || '').trim();
  if (rawJson) {
    try {
      const decoded = rawJson.startsWith('{')
        ? rawJson
        : Buffer.from(rawJson, 'base64').toString('utf8');
      const parsed = JSON.parse(decoded) as Record<string, unknown>;
      const clientEmail = String(parsed.client_email || '').trim();
      const privateKey = String(parsed.private_key || '').replace(/\\n/g, '\n').trim();
      const projectId = String(parsed.project_id || requestedProjectId || '').trim();
      if (clientEmail && privateKey && projectId) {
        if (requestedProjectId && projectId !== requestedProjectId) {
          return null;
        }
        return { projectId, clientEmail, privateKey };
      }
    } catch {
      // Ignore invalid JSON and try individual env vars
    }
  }

  const clientEmail = (process.env.FIREBASE_CLIENT_EMAIL || '').trim();
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();
  const defaults = getBundledFirebaseDefaults();
  const projectId = (
    process.env.FIREBASE_PROJECT_ID ||
    requestedProjectId ||
    defaults.projectId
  ).trim();

  if (clientEmail && privateKey && projectId) {
    if (requestedProjectId && projectId !== requestedProjectId) {
      return null;
    }
    return { projectId, clientEmail, privateKey };
  }
  return null;
}

export function resolveTargetFirebase(req: ApiRequest): {
  projectId: string;
  databaseId: string;
} {
  const defaults = getBundledFirebaseDefaults();
  const rawProj = req.headers['x-firebase-project-id'];
  const rawDb = req.headers['x-firestore-database-id'];
  const projectId = (Array.isArray(rawProj) ? rawProj[0] : rawProj || defaults.projectId || '').trim();
  const dbIdRaw = (Array.isArray(rawDb) ? rawDb[0] : rawDb || defaults.firestoreDatabaseId || '(default)').trim();
  return {
    projectId,
    databaseId: dbIdRaw || '(default)',
  };
}

let cachedCerts: { map: Record<string, string>; expiresAtMs: number } | null = null;
async function getFirebasePublicCerts(): Promise<Record<string, string>> {
  if (cachedCerts && Date.now() < cachedCerts.expiresAtMs) {
    return cachedCerts.map;
  }
  const resp = await fetch(
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
  );
  if (!resp.ok) {
    throw new Error('Unable to fetch Firebase public verification certificates.');
  }
  const cacheControl = resp.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const ttlMs = maxAgeMatch ? Number(maxAgeMatch[1]) * 1000 : 300_000;
  const map = (await resp.json()) as Record<string, string>;
  cachedCerts = { map, expiresAtMs: Date.now() + Math.min(ttlMs, 3_600_000) };
  return map;
}

function decodeBase64Url(str: string): Buffer {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padLen), 'base64');
}

export async function verifyFirebaseIdToken(
  req: ApiRequest,
  expectedProjectId: string,
): Promise<{ auth?: VerifiedIdToken; status?: number; error?: string }> {
  const authHeader = req.headers.authorization;
  const headerStr = Array.isArray(authHeader) ? authHeader[0] : String(authHeader || '');
  const match = headerStr.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return { status: 401, error: 'Missing Authorization Bearer token' };
  }

  const token = match[1].trim();
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { status: 401, error: 'Malformed ID token' };
  }

  try {
    const header = JSON.parse(decodeBase64Url(parts[0]).toString('utf8')) as {
      alg?: string;
      kid?: string;
    };
    const payload = JSON.parse(decodeBase64Url(parts[1]).toString('utf8')) as {
      aud?: string;
      iss?: string;
      sub?: string;
      user_id?: string;
      email?: string;
      email_verified?: boolean;
      exp?: number;
      iat?: number;
    };

    if (header.alg !== 'RS256' || !header.kid) {
      return { status: 401, error: 'Unsupported token algorithm' };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp <= nowSec) {
      return { status: 401, error: 'Authentication token expired' };
    }
    if (!payload.aud || payload.aud !== expectedProjectId) {
      return { status: 401, error: 'Token project mismatch' };
    }
    if (payload.iss !== `https://securetoken.google.com/${expectedProjectId}`) {
      return { status: 401, error: 'Token issuer mismatch' };
    }

    const certs = await getFirebasePublicCerts();
    const cert = certs[header.kid];
    if (!cert) {
      return { status: 401, error: 'Token signing key not found' };
    }

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${parts[0]}.${parts[1]}`);
    const sigValid = verifier.verify(cert, decodeBase64Url(parts[2]));
    if (!sigValid) {
      return { status: 401, error: 'Invalid Firebase ID token signature' };
    }

    const uid = String(payload.sub || payload.user_id || '').trim();
    if (!uid) {
      return { status: 401, error: 'Token missing uid' };
    }
    if (!payload.email_verified) {
      return { status: 403, error: 'Verified email required' };
    }

    return {
      auth: {
        uid,
        email: String(payload.email || ''),
        emailVerified: Boolean(payload.email_verified),
      },
    };
  } catch {
    return { status: 401, error: 'Invalid or expired Firebase ID token' };
  }
}

const tokenCache = new Map<string, { token: string; expiresAtMs: number }>();

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function getGoogleAccessToken(creds: ServiceAccountCreds): Promise<string> {
  const cacheKey = `${creds.projectId}:${creds.clientEmail}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAtMs) {
    return cached.token;
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim = base64UrlEncode(
    JSON.stringify({
      iss: creds.clientEmail,
      scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token',
      iat: nowSec,
      exp: nowSec + 3600,
    }),
  );
  const signingInput = `${header}.${claim}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  const signature = base64UrlEncode(signer.sign(creds.privateKey));
  const assertion = `${signingInput}.${signature}`;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    throw new Error(`Service account auth failed (${resp.status}): ${errText.slice(0, 120)}`);
  }

  const data = (await resp.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) {
    throw new Error('OAuth2 token response missing access_token');
  }

  tokenCache.set(cacheKey, {
    token: data.access_token,
    expiresAtMs: Date.now() + Math.max(60, (data.expires_in || 3600) - 180) * 1000,
  });
  return data.access_token;
}

export async function createFirestoreContext(
  projectId: string,
  databaseId: string,
): Promise<FirestoreRestContext | null> {
  const creds = getServiceAccountCreds(projectId);
  if (!creds) return null;
  const accessToken = await getGoogleAccessToken(creds);
  return {
    projectId: creds.projectId,
    databaseId: databaseId || '(default)',
    accessToken,
  };
}

export const SERVER_TIMESTAMP_SENTINEL = { __serverTimestamp: true } as const;

export function toFirestoreValue(val: unknown): Record<string, unknown> {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'number') {
    if (Number.isInteger(val)) return { integerValue: String(val) };
    return { doubleValue: val };
  }
  if (typeof val === 'string') return { stringValue: val };
  if (val instanceof Date) return { timestampValue: val.toISOString() };
  if (Array.isArray(val)) {
    return { arrayValue: { values: val.map((item) => toFirestoreValue(item)) } };
  }
  if (typeof val === 'object') {
    const fields: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (v !== undefined && v !== SERVER_TIMESTAMP_SENTINEL) {
        fields[k] = toFirestoreValue(v);
      }
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

export function fromFirestoreValue(v: unknown): unknown {
  if (!v || typeof v !== 'object') return null;
  const obj = v as Record<string, unknown>;
  if ('nullValue' in obj) return null;
  if ('booleanValue' in obj) return Boolean(obj.booleanValue);
  if ('integerValue' in obj) return Number(obj.integerValue);
  if ('doubleValue' in obj) return Number(obj.doubleValue);
  if ('stringValue' in obj) return String(obj.stringValue);
  if ('timestampValue' in obj) {
    const ms = Date.parse(String(obj.timestampValue));
    return Number.isFinite(ms) ? ms : 0;
  }
  if ('arrayValue' in obj) {
    const arr = (obj.arrayValue as { values?: unknown[] })?.values || [];
    return arr.map((item) => fromFirestoreValue(item));
  }
  if ('mapValue' in obj) {
    const fields = (obj.mapValue as { fields?: Record<string, unknown> })?.fields || {};
    const out: Record<string, unknown> = {};
    for (const [k, fv] of Object.entries(fields)) {
      out[k] = fromFirestoreValue(fv);
    }
    return out;
  }
  return null;
}

export function decodeFirestoreDocument(docJson: {
  name?: string;
  fields?: Record<string, unknown>;
}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const fields = docJson.fields || {};
  for (const [k, v] of Object.entries(fields)) {
    out[k] = fromFirestoreValue(v);
  }
  return out;
}

export function encodeFirestoreFields(data: Record<string, unknown>): {
  fields: Record<string, unknown>;
  serverTimestampFields: string[];
} {
  const fields: Record<string, unknown> = {};
  const serverTimestampFields: string[] = [];
  for (const [k, v] of Object.entries(data)) {
    if (v === SERVER_TIMESTAMP_SENTINEL) {
      serverTimestampFields.push(k);
    } else if (v !== undefined) {
      fields[k] = toFirestoreValue(v);
    }
  }
  return { fields, serverTimestampFields };
}

function docResourceName(ctx: FirestoreRestContext, docPath: string): string {
  const clean = docPath.replace(/^\/+/, '');
  return `projects/${ctx.projectId}/databases/${ctx.databaseId}/documents/${clean}`;
}

function dbBaseUrl(ctx: FirestoreRestContext): string {
  return `https://firestore.googleapis.com/v1/projects/${ctx.projectId}/databases/${ctx.databaseId}/documents`;
}

export async function fsGetDoc(
  ctx: FirestoreRestContext,
  docPath: string,
  transaction?: string,
): Promise<{ exists: boolean; data: Record<string, unknown> }> {
  const url = `${dbBaseUrl(ctx)}/${docPath.replace(/^\/+/, '')}${
    transaction ? `?transaction=${encodeURIComponent(transaction)}` : ''
  }`;
  const resp = await fetch(url, {
    headers: { Authorization: `Bearer ${ctx.accessToken}` },
  });
  if (resp.status === 404) {
    return { exists: false, data: {} };
  }
  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    throw new Error(`Firestore GET ${docPath} failed (${resp.status}): ${txt.slice(0, 160)}`);
  }
  const json = (await resp.json()) as { fields?: Record<string, unknown> };
  return { exists: true, data: decodeFirestoreDocument(json) };
}

export async function fsQueryEq(
  ctx: FirestoreRestContext,
  collectionId: string,
  fieldPath: string,
  value: string,
  limit = 20,
): Promise<Array<{ id: string; data: Record<string, unknown> }>> {
  const resp = await fetch(`${dbBaseUrl(ctx)}:runQuery`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ctx.accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      structuredQuery: {
        from: [{ collectionId }],
        where: {
          fieldFilter: {
            field: { fieldPath },
            op: 'EQUAL',
            value: { stringValue: value },
          },
        },
        limit,
      },
    }),
  });
  if (!resp.ok) return [];
  const rows = (await resp.json()) as Array<{
    document?: { name?: string; fields?: Record<string, unknown> };
  }>;
  return rows
    .filter((r) => Boolean(r.document))
    .map((r) => {
      const name = String(r.document?.name || '');
      const id = name.split('/').pop() || '';
      return { id, data: decodeFirestoreDocument(r.document!) };
    });
}

export async function fsBeginTransaction(ctx: FirestoreRestContext): Promise<string> {
  const resp = await fetch(`${dbBaseUrl(ctx)}:beginTransaction`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ctx.accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ options: { readWrite: {} } }),
  });
  if (!resp.ok) {
    throw new Error(`beginTransaction failed (${resp.status})`);
  }
  const json = (await resp.json()) as { transaction?: string };
  if (!json.transaction) {
    throw new Error('beginTransaction response missing token');
  }
  return json.transaction;
}

export function buildSetWrite(
  ctx: FirestoreRestContext,
  docPath: string,
  data: Record<string, unknown>,
  options: { createOnly?: boolean; mergeFields?: string[] } = {},
): Array<Record<string, unknown>> {
  const name = docResourceName(ctx, docPath);
  const { fields, serverTimestampFields } = encodeFirestoreFields(data);
  const writes: Array<Record<string, unknown>> = [];

  const updateWrite: Record<string, unknown> = {
    update: { name, fields },
    ...(options.createOnly ? { currentDocument: { exists: false } } : {}),
    ...(options.mergeFields ? { updateMask: { fieldPaths: options.mergeFields } } : {}),
  };
  writes.push(updateWrite);

  if (serverTimestampFields.length > 0) {
    writes.push({
      transform: {
        document: name,
        fieldTransforms: serverTimestampFields.map((fieldPath) => ({
          fieldPath,
          setToServerValue: 'REQUEST_TIME',
        })),
      },
    });
  }

  return writes;
}

export async function fsCommit(
  ctx: FirestoreRestContext,
  writes: Array<Record<string, unknown>>,
  transaction?: string,
): Promise<void> {
  const resp = await fetch(`${dbBaseUrl(ctx)}:commit`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ctx.accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ...(transaction ? { transaction } : {}),
      writes,
    }),
  });
  if (!resp.ok) {
    const txt = await resp.text().catch(() => '');
    throw new Error(`Firestore commit failed (${resp.status}): ${txt.slice(0, 180)}`);
  }
}

export async function fsRollback(ctx: FirestoreRestContext, transaction: string): Promise<void> {
  await fetch(`${dbBaseUrl(ctx)}:rollback`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${ctx.accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ transaction }),
  }).catch(() => {});
}
