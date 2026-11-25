import type { ServerResponse } from 'node:http';
import {
  type ApiRequest,
  applyCors,
  buildSetWrite,
  createFirestoreContext,
  fsCommit,
  fsGetDoc,
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendJson,
  verifyFirebaseIdToken,
} from './_firebaseAdminRest.ts';

export default async function handler(req: ApiRequest, res: ServerResponse): Promise<void> {
  if (req.method === 'OPTIONS') {
    applyCors(res);
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendJson(res, 405, { ok: false, error: 'Method not allowed' });
    return;
  }

  const { projectId, databaseId } = resolveTargetFirebase(req);
  if (!projectId) {
    sendJson(res, 503, {
      ok: false,
      backendConfigured: false,
      error: 'SERVER_CREDENTIALS_MISSING',
    });
    return;
  }

  const authCheck = await verifyFirebaseIdToken(req, projectId);
  if (!authCheck.auth) {
    sendJson(res, authCheck.status || 401, { ok: false, error: authCheck.error || 'Unauthorized' });
    return;
  }

  const ctx = await createFirestoreContext(projectId, databaseId);
  if (!ctx) {
    sendJson(res, 503, {
      ok: false,
      backendConfigured: false,
      error: 'SERVER_CREDENTIALS_MISSING',
    });
    return;
  }

  const body = await readJsonBody(req);
  const sessionId = sanitizeId(String(body.sessionId || '').trim());
  const reason = String(body.reason || 'CLOSED_BEFORE_30_SECONDS').trim().slice(0, 180);
  if (!sessionId) {
    sendJson(res, 400, { ok: false, error: 'Missing sessionId' });
    return;
  }

  try {
    const snap = await fsGetDoc(ctx, `adSessions/${sessionId}`);
    if (!snap.exists) {
      sendJson(res, 404, { ok: false, error: 'SESSION_NOT_FOUND' });
      return;
    }
    if (snap.data.userId !== authCheck.auth.uid) {
      sendJson(res, 403, { ok: false, error: 'SESSION_MISMATCH' });
      return;
    }
    if (snap.data.status !== 'pending') {
      sendJson(res, 200, { ok: true, status: String(snap.data.status || '') });
      return;
    }

    const writes = buildSetWrite(
      ctx,
      `adSessions/${sessionId}`,
      { status: 'rejected', rejectionReason: reason || 'CLOSED_BEFORE_30_SECONDS' },
      { mergeFields: ['status', 'rejectionReason'] },
    );
    await fsCommit(ctx, writes);
    sendJson(res, 200, { ok: true, status: 'rejected' });
  } catch (err) {
    sendJson(res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'CANCEL_SESSION_FAILED',
    });
  }
}
