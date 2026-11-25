import crypto from 'node:crypto';
import type { ServerResponse } from 'node:http';
import {
  type ApiRequest,
  applyCors,
  buildSetWrite,
  createFirestoreContext,
  DAILY_CHECKIN_BONUS_AD_ID,
  DEFAULT_GLOBAL_DAILY_AD_LIMIT,
  fsCommit,
  fsGetDoc,
  getDhakaDateKey,
  normalizeAdDurationSeconds,
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendJson,
  SERVER_TIMESTAMP_SENTINEL,
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
      status: 'backend_unavailable',
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
      status: 'backend_unavailable',
      backendConfigured: false,
      error: 'SERVER_CREDENTIALS_MISSING',
    });
    return;
  }

  const body = await readJsonBody(req);
  const adId = sanitizeId(String(body.adId || ''));
  if (!adId) {
    sendJson(res, 400, { ok: false, error: 'Missing adId' });
    return;
  }
  if (adId === DAILY_CHECKIN_BONUS_AD_ID) {
    sendJson(res, 403, { ok: false, error: 'USE_DAILY_BONUS_ENDPOINT' });
    return;
  }

  const uid = authCheck.auth.uid;
  const dhakaToday = getDhakaDateKey();
  const sessionId = sanitizeId(
    `sess_${Date.now()}_${uid.slice(0, 6)}_${crypto.randomBytes(6).toString('hex')}`,
  );

  try {
    const [walletSettingsSnap, userSnap, adSnap, dailySnap] = await Promise.all([
      fsGetDoc(ctx, 'appSettings/wallet'),
      fsGetDoc(ctx, `users/${uid}`),
      fsGetDoc(ctx, `advertisements/${adId}`),
      fsGetDoc(ctx, `dailyAdLimits/${uid}_${dhakaToday}`),
    ]);

    const earningEnabled =
      walletSettingsSnap.exists && typeof walletSettingsSnap.data.earningEnabled === 'boolean'
        ? Boolean(walletSettingsSnap.data.earningEnabled)
        : true;
    const dailyAdLimit = Math.max(
      1,
      Number(walletSettingsSnap.data.dailyAdLimit || DEFAULT_GLOBAL_DAILY_AD_LIMIT),
    );

    if (!earningEnabled) {
      sendJson(res, 403, { ok: false, error: 'EARNING_DISABLED' });
      return;
    }
    if (!userSnap.exists || userSnap.data.accountStatus !== 'active') {
      sendJson(res, 403, { ok: false, error: 'USER_NOT_ACTIVE' });
      return;
    }
    if (!adSnap.exists) {
      sendJson(res, 404, { ok: false, error: 'AD_NOT_FOUND' });
      return;
    }

    const adData = adSnap.data;
    if (adData.status !== 'active' || adData.rewardVerificationMethod === 'none') {
      sendJson(res, 403, { ok: false, error: 'AD_NOT_ELIGIBLE' });
      return;
    }
    if (adData.adType === 'direct_link' && adData.incentivizedTrafficAllowed !== true) {
      sendJson(res, 403, { ok: false, error: 'INCENTIVIZED_TRAFFIC_DISALLOWED' });
      return;
    }

    const adNetLower = String(adData.adNetwork || '').toLowerCase();
    const placementStr = String(adData.placementOrUrl || '').trim();
    if (adNetLower.includes('applixir') || /^applixir:/i.test(placementStr)) {
      sendJson(res, 412, { ok: false, error: 'APPLIXIR_NOT_CONFIGURED' });
      return;
    }

    const completedCount = Number(dailySnap.data.completedCount || 0);
    const completedAdIds: string[] = Array.isArray(dailySnap.data.completedAdIds)
      ? (dailySnap.data.completedAdIds as unknown[]).map((x) => String(x))
      : [];

    if (completedCount >= dailyAdLimit) {
      sendJson(res, 429, { ok: false, error: 'GLOBAL_DAILY_LIMIT_REACHED' });
      return;
    }
    if (completedAdIds.filter((id) => id === adId).length >= Math.max(1, Number(adData.dailyLimit || 1))) {
      sendJson(res, 429, { ok: false, error: 'PER_AD_DAILY_LIMIT_REACHED' });
      return;
    }

    const requiredDurationSec = normalizeAdDurationSeconds(adData.estimatedDuration);
    const writes = buildSetWrite(
      ctx,
      `adSessions/${sessionId}`,
      {
        sessionId,
        userId: uid,
        adId,
        adName: String(adData.adName || 'Sponsored Ad').slice(0, 100),
        adNetwork: String(adData.adNetwork || 'Partner Network').slice(0, 60),
        expectedRewardPoints: Number(adData.rewardPoints || 0),
        dhakaDate: dhakaToday,
        status: 'pending',
        transactionId: '',
        rejectionReason: '',
        createdAt: SERVER_TIMESTAMP_SENTINEL,
      },
      { createOnly: true },
    );
    await fsCommit(ctx, writes);

    sendJson(res, 200, {
      ok: true,
      sessionId,
      adId,
      dhakaDate: dhakaToday,
      requiredDurationSec,
    });
  } catch (err) {
    sendJson(res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'CREATE_AD_SESSION_FAILED',
    });
  }
}
