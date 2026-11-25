import type { ServerResponse } from 'node:http';
import { FieldValue } from 'firebase-admin/firestore';
import {
  type ApiRequest,
  applyCors,
  DAILY_CHECKIN_BONUS_AD_ID,
  getAppLixirBackendEnvStatus,
  getDhakaDateKey,
  getFirebaseAdminContext,
  isCredentialOrPermissionError,
  isValidAppLixirSiteOrKey,
  normalizeAdDurationSeconds,
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendBackendUnavailable,
  sendJson,
  verifyAuthAndRoleAdmin,
} from './_firebaseAdmin.ts';
import {
  enforceRateLimitAdmin,
  generateSessionId,
  readActiveAppSettingsAdmin,
} from './_rewardEngine.ts';

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

  const body = await readJsonBody(req);
  const adId = sanitizeId(String(body.adId || ''));
  if (!adId || !String(body.adId || '').trim()) {
    sendJson(req, res, 400, { ok: false, error: 'Missing adId' });
    return;
  }
  if (adId === DAILY_CHECKIN_BONUS_AD_ID) {
    sendJson(req, res, 403, { ok: false, error: 'USE_DAILY_BONUS_ENDPOINT' });
    return;
  }

  const uid = authCheck.auth.uid;

  try {
    const rate = await enforceRateLimitAdmin(ctx, {
      bucketKey: `ad_sess_${uid}`,
      actionName: 'createAdSession',
      actorId: uid,
      maxRequests: 15,
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
    const sessionId = generateSessionId('sess', uid);

    const [settings, userSnap, adSnapPrimary, directLinkSnap, dailySnap] = await Promise.all([
      readActiveAppSettingsAdmin(ctx),
      ctx.db.collection('users').doc(uid).get(),
      ctx.db.collection('advertisements').doc(adId).get(),
      ctx.db.collection('directLinkAds').doc(adId).get(),
      ctx.db.collection('dailyAdLimits').doc(`${uid}_${dhakaToday}`).get(),
    ]);

    if (!settings.earningEnabled) {
      sendJson(req, res, 403, { ok: false, error: 'EARNING_DISABLED' });
      return;
    }
    if (!userSnap.exists || userSnap.data()!.accountStatus !== 'active') {
      sendJson(req, res, 403, { ok: false, error: 'USER_NOT_ACTIVE' });
      return;
    }
    const adSnap = adSnapPrimary.exists ? adSnapPrimary : directLinkSnap;
    if (!adSnap.exists) {
      sendJson(req, res, 404, { ok: false, error: 'AD_NOT_FOUND' });
      return;
    }

    const adData = adSnap.data()!;
    const isDirectLinkDoc = !adSnapPrimary.exists && directLinkSnap.exists;
    if (adData.status !== 'active' || adData.rewardVerificationMethod === 'none') {
      sendJson(req, res, 403, { ok: false, error: 'AD_NOT_ELIGIBLE' });
      return;
    }
    if ((isDirectLinkDoc || adData.adType === 'direct_link') && adData.incentivizedTrafficAllowed !== true) {
      sendJson(req, res, 403, { ok: false, error: 'INCENTIVIZED_TRAFFIC_DISALLOWED' });
      return;
    }

    const adNetLower = String(adData.adNetwork || '').toLowerCase();
    const placementStr = String(adData.placementOrUrl || adData.url || '').trim();
    const isAppLixirAd = adNetLower.includes('applixir') || /^applixir:/i.test(placementStr);

    if (isAppLixirAd) {
      if (adData.rewardVerificationMethod !== 's2s_postback') {
        sendJson(req, res, 403, { ok: false, error: 'S2S_POSTBACK_REQUIRED' });
        return;
      }
      const [appNetSnap, appSecSnap] = await Promise.all([
        ctx.db.collection('adNetworks').doc('applixir').get(),
        ctx.db.collection('adNetworkSecrets').doc('applixir').get(),
      ]);
      const appNet = appNetSnap.exists ? appNetSnap.data()! : null;
      const appSec = appSecSnap.exists ? appSecSnap.data()! : {};
      if (appNet && appNet.enabled === false) {
        sendJson(req, res, 403, { ok: false, error: 'NETWORK_DISABLED' });
        return;
      }
      if (appNet && appNet.rewardEnabled === false) {
        sendJson(req, res, 403, { ok: false, error: 'NETWORK_REWARD_NOT_ELIGIBLE' });
        return;
      }

      const envStatus = getAppLixirBackendEnvStatus();
      const hasSiteId =
        isValidAppLixirSiteOrKey(placementStr) ||
        isValidAppLixirSiteOrKey(String(appNet?.websiteId || '')) ||
        isValidAppLixirSiteOrKey(String(appNet?.placementId || '')) ||
        envStatus.siteIdConfigured;
      const hasSecretKey =
        envStatus.secretKeyConfigured || Boolean(String(appSec.callbackSecret || '').trim());
      const hasApiKey =
        envStatus.apiKeyConfigured || Boolean(String(appSec.apiKey || '').trim());

      if (!hasSiteId || !hasSecretKey || !hasApiKey) {
        sendJson(req, res, 412, {
          ok: false,
          error: 'APPLIXIR_NOT_CONFIGURED',
          missing: {
            siteId: !hasSiteId,
            apiKey: !hasApiKey,
            secretKey: !hasSecretKey,
          },
        });
        return;
      }
    }

    const daily = dailySnap.exists ? dailySnap.data()! : {};
    const completedCount = Number(daily.completedCount || 0);
    const completedAdIds: string[] = Array.isArray(daily.completedAdIds)
      ? daily.completedAdIds.map((x: unknown) => String(x))
      : [];

    if (completedCount >= settings.dailyAdLimit) {
      sendJson(req, res, 429, { ok: false, error: 'GLOBAL_DAILY_LIMIT_REACHED' });
      return;
    }
    const perAdCount = completedAdIds.filter((id) => id === adId).length;
    if (perAdCount >= Math.max(1, Number(adData.dailyLimit || 1))) {
      sendJson(req, res, 429, { ok: false, error: 'PER_AD_DAILY_LIMIT_REACHED' });
      return;
    }

    const requiredDurationSec = normalizeAdDurationSeconds(adData.estimatedDuration);

    await ctx.db.collection('adSessions').doc(sessionId).create({
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
      createdAt: FieldValue.serverTimestamp(),
    });

    sendJson(req, res, 200, {
      ok: true,
      sessionId,
      ymid: sessionId,
      adId,
      dhakaDate: dhakaToday,
      requiredDurationSec,
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
      error: err instanceof Error ? err.message : 'CREATE_AD_SESSION_FAILED',
    });
  }
}
