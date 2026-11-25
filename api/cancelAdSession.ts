import type { ServerResponse } from 'node:http';
import {
  type ApiRequest,
  applyCors,
  getFirebaseAdminContext,
  isCredentialOrPermissionError,
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendBackendUnavailable,
  sendJson,
  verifyAuthAndRoleAdmin,
} from './_firebaseAdmin.ts';

export default async function handler(req: ApiRequest, res: ServerResponse): Promise<void> {
  if (req.method === 'OPTIONS') {
    applyCors(req, res);
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== 'POST') {
    sendJson(req, res, 405, { ok: false, error: 'Method not allowed' });
    return;
  }

  const { projectId, databaseId } = resolveTargetFirebase(req);
  const ctx = getFirebaseAdminContext(projectId, databaseId);
  if (!ctx) {
    sendBackendUnavailable(req, res);
    return;
  }

  const authCheck = await verifyAuthAndRoleAdmin(req, ctx, { requireVerifiedEmail: true });
  if (!authCheck.auth) {
    sendJson(req, res, authCheck.status || 401, {
      ok: false,
      error: authCheck.error || 'Unauthorized',
    });
    return;
  }

  const uid = authCheck.auth.uid;
  const body = await readJsonBody(req);
  const sessionId = sanitizeId(String(body.sessionId || '').trim());
  const reason = String(body.reason || 'CLOSED_BEFORE_30_SECONDS').trim().slice(0, 180);

  if (!sessionId || !String(body.sessionId || '').trim()) {
    sendJson(req, res, 400, { ok: false, error: 'Missing sessionId' });
    return;
  }

  try {
    const sessionRef = ctx.db.collection('adSessions').doc(sessionId);
    const result = await ctx.db.runTransaction(async (txn) => {
      const snap = await txn.get(sessionRef);
      if (!snap.exists) {
        return { found: false, alreadyFinalized: false };
      }
      const data = snap.data()!;
      if (data.userId !== uid) {
        throw new Error('SESSION_MISMATCH');
      }
      if (data.status !== 'pending') {
        return { found: true, alreadyFinalized: true, status: String(data.status) };
      }
      txn.update(sessionRef, {
        status: 'rejected',
        rejectionReason: reason || 'CLOSED_BEFORE_30_SECONDS',
      });
      return { found: true, alreadyFinalized: false, status: 'rejected' };
    });

    sendJson(req, res, 200, { ok: true, ...result });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(req, res);
      return;
    }
    const code = err instanceof Error ? err.message : 'CANCEL_SESSION_FAILED';
    sendJson(req, res, code === 'SESSION_MISMATCH' ? 403 : 500, { ok: false, error: code });
  }
}
