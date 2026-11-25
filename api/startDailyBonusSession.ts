import crypto from 'node:crypto';
import type { ServerResponse } from 'node:http';
import {
  type ApiRequest,
  applyCors,
  buildSetWrite,
  createFirestoreContext,
  DAILY_CHECKIN_BONUS_AD_ID,
  fsCommit,
  fsGetDoc,
  getDhakaDateKey,
  normalizeAdDurationSeconds,
  resolveTargetFirebase,
  sanitizeId,
  sendJson,
  SERVER_TIMESTAMP_SENTINEL,
  verifyFirebaseIdToken,
} from './_firebaseAdminRest.ts';

function injectTrackingParams(rawUrl: string, sessionId: string, userId: string, adId: string): string {
  try {
    const u = new URL(rawUrl);
    if (!u.searchParams.has('ymid')) u.searchParams.set('ymid', sessionId);
    if (!u.searchParams.has('var')) u.searchParams.set('var', userId);
    if (!u.searchParams.has('sub1')) u.searchParams.set('sub1', adId);
    return u.toString();
  } catch {
    return rawUrl;
  }
}

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

  const uid = authCheck.auth.uid;
  const dhakaToday = getDhakaDateKey();
  const sessionId = sanitizeId(
    `sess_bonus_${Date.now()}_${uid.slice(0, 6)}_${crypto.randomBytes(5).toString('hex')}`,
  );

  try {
    const [walletSettingsSnap, economySnap, userSnap, bonusCfgSnap, userBonusSnap] =
      await Promise.all([
        fsGetDoc(ctx, 'appSettings/wallet'),
        fsGetDoc(ctx, 'appConfig/economy'),
        fsGetDoc(ctx, `users/${uid}`),
        fsGetDoc(ctx, 'appSettings/dailyBonus'),
        fsGetDoc(ctx, `dailyBonuses/${uid}`),
      ]);

    const earningEnabled =
      walletSettingsSnap.exists && typeof walletSettingsSnap.data.earningEnabled === 'boolean'
        ? Boolean(walletSettingsSnap.data.earningEnabled)
        : true;
    if (!earningEnabled) {
      sendJson(res, 403, { ok: false, error: 'EARNING_DISABLED' });
      return;
    }

    if (!userSnap.exists || userSnap.data.accountStatus !== 'active') {
      sendJson(res, 403, { ok: false, error: 'USER_NOT_ACTIVE' });
      return;
    }

    if (!bonusCfgSnap.exists) {
      sendJson(res, 412, { ok: false, error: 'DAILY_BONUS_NOT_CONFIGURED' });
      return;
    }

    const cfg = bonusCfgSnap.data;
    if (cfg.enabled !== true) {
      sendJson(res, 403, { ok: false, error: 'DAILY_BONUS_DISABLED' });
      return;
    }
    if (cfg.incentivizedTrafficAllowed !== true) {
      sendJson(res, 403, { ok: false, error: 'INCENTIVIZED_TRAFFIC_DISALLOWED' });
      return;
    }

    const rawUrl = String(cfg.monetagDirectLinkUrl || '').trim();
    if (!/^https:\/\/.+/i.test(rawUrl)) {
      sendJson(res, 412, { ok: false, error: 'DAILY_BONUS_NOT_CONFIGURED' });
      return;
    }

    const fallbackPoints = Number(
      walletSettingsSnap.data.dailyBonusPoints || economySnap.data.dailyBonusPoints || 0,
    );
    const rewardPoints = Math.max(0, Math.floor(Number(cfg.rewardPoints || fallbackPoints || 0)));
    if (rewardPoints < 1) {
      sendJson(res, 412, { ok: false, error: 'DAILY_BONUS_NOT_CONFIGURED' });
      return;
    }

    const durationSeconds = normalizeAdDurationSeconds(cfg.durationSeconds);
    const lastClaimDate = String(userBonusSnap.data.lastClaimDate || '');
    if (lastClaimDate === dhakaToday) {
      sendJson(res, 409, { ok: false, error: 'DAILY_BONUS_ALREADY_CLAIMED' });
      return;
    }

    const writes = buildSetWrite(
      ctx,
      `adSessions/${sessionId}`,
      {
        sessionId,
        userId: uid,
        adId: DAILY_CHECKIN_BONUS_AD_ID,
        adName: 'Daily Check-in Bonus',
        adNetwork: 'Monetag',
        expectedRewardPoints: rewardPoints,
        dhakaDate: dhakaToday,
        status: 'pending',
        transactionId: '',
        rejectionReason: '',
        createdAt: SERVER_TIMESTAMP_SENTINEL,
      },
      { createOnly: true },
    );
    await fsCommit(ctx, writes);

    const launchUrl = injectTrackingParams(rawUrl, sessionId, uid, DAILY_CHECKIN_BONUS_AD_ID);
    sendJson(res, 200, {
      ok: true,
      sessionId,
      adId: DAILY_CHECKIN_BONUS_AD_ID,
      dhakaDate: dhakaToday,
      rewardPoints,
      durationSeconds,
      launchUrl,
    });
  } catch (err) {
    sendJson(res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'DAILY_BONUS_START_FAILED',
    });
  }
}
