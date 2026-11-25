import type { ServerResponse } from 'node:http';
import { FieldValue } from 'firebase-admin/firestore';
import {
  type ApiRequest,
  applyCors,
  DAILY_CHECKIN_BONUS_AD_ID,
  getDhakaDateKey,
  getFirebaseAdminContext,
  isCredentialOrPermissionError,
  normalizeAdDurationSeconds,
  resolveTargetFirebase,
  sendBackendUnavailable,
  sendJson,
  verifyAuthAndRoleAdmin,
} from './_firebaseAdmin.ts';
import {
  enforceRateLimitAdmin,
  generateSessionId,
  readActiveAppSettingsAdmin,
} from './_rewardEngine.ts';

function buildServerDailyBonusLaunchUrl(
  rawUrl: string,
  sessionId: string,
  userId: string,
): string | null {
  const trimmed = rawUrl.trim();
  if (!/^https:\/\/.+/i.test(trimmed)) return null;
  try {
    const resolved = trimmed
      .replace(/\{sessionId\}|\{session_id\}|\{ymid\}/gi, encodeURIComponent(sessionId))
      .replace(/\{userId\}|\{user_id\}|\{var\}|\{request_var\}/gi, encodeURIComponent(userId))
      .replace(/\{adId\}|\{ad_id\}/gi, encodeURIComponent(DAILY_CHECKIN_BONUS_AD_ID));
    const parsed = new URL(resolved);
    if (parsed.protocol !== 'https:') return null;
    if (!parsed.searchParams.has('ymid')) parsed.searchParams.set('ymid', sessionId);
    if (!parsed.searchParams.has('var')) parsed.searchParams.set('var', userId);
    return parsed.toString();
  } catch {
    return null;
  }
}

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

  try {
    const rate = await enforceRateLimitAdmin(ctx, {
      bucketKey: `daily_bonus_sess_${uid}`,
      actionName: 'startDailyBonusSession',
      actorId: uid,
      maxRequests: 10,
      windowSeconds: 60,
    });
    if (!rate.allowed) {
      sendJson(req, res, 429, {
        ok: false,
        error: 'RATE_LIMIT_EXCEEDED',
        retryAfterSec: rate.retryAfterSec,
      });
      return;
    }

    const dhakaToday = getDhakaDateKey();
    const sessionId = generateSessionId('bonus', uid);

    const [settings, userSnap, dailyBonusSnap, bonusCfgSnap, monetagNetSnap] = await Promise.all([
      readActiveAppSettingsAdmin(ctx),
      ctx.db.collection('users').doc(uid).get(),
      ctx.db.collection('dailyBonuses').doc(uid).get(),
      ctx.db.collection('appSettings').doc('dailyBonus').get(),
      ctx.db.collection('adNetworks').doc('monetag').get(),
    ]);

    if (!settings.earningEnabled) {
      sendJson(req, res, 403, { ok: false, error: 'EARNING_DISABLED' });
      return;
    }
    if (!userSnap.exists || userSnap.data()!.accountStatus !== 'active') {
      sendJson(req, res, 403, { ok: false, error: 'USER_NOT_ACTIVE' });
      return;
    }

    const lastClaimDate = dailyBonusSnap.exists
      ? String(dailyBonusSnap.data()!.lastClaimDate || '')
      : '';
    if (lastClaimDate === dhakaToday) {
      sendJson(req, res, 409, { ok: false, error: 'DAILY_BONUS_ALREADY_CLAIMED' });
      return;
    }

    if (!bonusCfgSnap.exists) {
      sendJson(req, res, 412, { ok: false, error: 'DAILY_BONUS_NOT_CONFIGURED' });
      return;
    }
    const cfg = bonusCfgSnap.data()!;
    if (cfg.enabled !== true) {
      sendJson(req, res, 403, { ok: false, error: 'DAILY_BONUS_DISABLED' });
      return;
    }
    if (cfg.incentivizedTrafficAllowed !== true) {
      sendJson(req, res, 403, { ok: false, error: 'INCENTIVIZED_TRAFFIC_DISALLOWED' });
      return;
    }

    const rawUrl = String(cfg.monetagDirectLinkUrl || '').trim();
    const launchUrl = buildServerDailyBonusLaunchUrl(rawUrl, sessionId, uid);
    if (!launchUrl) {
      sendJson(req, res, 412, { ok: false, error: 'DAILY_BONUS_NOT_CONFIGURED' });
      return;
    }

    const rewardPoints = Math.max(
      0,
      Math.floor(Number(cfg.rewardPoints || settings.dailyBonusPoints || 0)),
    );
    if (rewardPoints <= 0) {
      sendJson(req, res, 412, { ok: false, error: 'DAILY_BONUS_NOT_CONFIGURED' });
      return;
    }

    if (monetagNetSnap.exists && monetagNetSnap.data()!.enabled === false) {
      sendJson(req, res, 403, { ok: false, error: 'NETWORK_DISABLED' });
      return;
    }

    const durationSeconds = normalizeAdDurationSeconds(cfg.durationSeconds);

    await ctx.db.collection('adSessions').doc(sessionId).create({
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
      createdAt: FieldValue.serverTimestamp(),
    });

    sendJson(req, res, 200, {
      ok: true,
      sessionId,
      ymid: sessionId,
      adId: DAILY_CHECKIN_BONUS_AD_ID,
      dhakaDate: dhakaToday,
      rewardPoints,
      durationSeconds,
      launchUrl,
    });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(
        req,
        res,
        'Firebase Admin credentials lack Firestore access for this project.',
      );
      return;
    }
    sendJson(req, res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'START_DAILY_BONUS_SESSION_FAILED',
    });
  }
}
