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
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendBackendUnavailable,
  sendJson,
  toMillis,
  verifyAuthAndRoleAdmin,
} from './_firebaseAdmin.ts';
import {
  enforceRateLimitAdmin,
  executeVerifiedAdRewardTransactionAdmin,
  processReferralQualificationAdmin,
  recordAdAnalyticsDeltaAdmin,
  writeAdNetworkLogAdmin,
  writeSecurityAuditLogAdmin,
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

  const uid = authCheck.auth.uid;

  try {
    const sdkRate = await enforceRateLimitAdmin(ctx, {
      bucketKey: `sdk_reward_${uid}`,
      actionName: 'confirmSdkAdCompletion',
      actorId: uid,
      maxRequests: 15,
      windowSeconds: 60,
    });
    if (!sdkRate.allowed) {
      sendJson(req, res, 429, {
        ok: false,
        error: 'RATE_LIMIT_EXCEEDED',
        retryAfterSec: sdkRate.retryAfterSec,
      });
      return;
    }

    const body = await readJsonBody(req);
    const sessionId = sanitizeId(String(body.sessionId || '').trim());
    const adId = sanitizeId(String(body.adId || '').trim());
    const rawSdkZone = String(body.sdkZoneId || '').trim();
    const sdkZoneId = rawSdkZone.replace(/[^a-zA-Z0-9_.\-/]/g, '');
    const sdkVerified = body.sdkVerified === true;
    const watchedSeconds = Number(body.watchedSeconds || 0);
    const platformContext = String(body.platformContext || '').trim();

    if (!sessionId || !adId || !sdkVerified || !sdkZoneId) {
      sendJson(req, res, 400, { ok: false, error: 'SDK_VERIFICATION_INCOMPLETE' });
      return;
    }
    if (adId === DAILY_CHECKIN_BONUS_AD_ID) {
      sendJson(req, res, 403, { ok: false, error: 'S2S_POSTBACK_REQUIRED_FOR_DIRECT_LINK' });
      return;
    }

    const [sessionSnap, adSnap] = await Promise.all([
      ctx.db.collection('adSessions').doc(sessionId).get(),
      ctx.db.collection('advertisements').doc(adId).get(),
    ]);

    if (!sessionSnap.exists) {
      sendJson(req, res, 404, { ok: false, error: 'SESSION_NOT_FOUND' });
      return;
    }
    const sessionData = sessionSnap.data()!;
    if (sessionData.userId !== uid || sessionData.adId !== adId) {
      sendJson(req, res, 403, { ok: false, error: 'SESSION_MISMATCH' });
      return;
    }
    if (sessionData.status !== 'pending') {
      sendJson(req, res, 409, { ok: false, error: 'SESSION_ALREADY_FINALIZED' });
      return;
    }
    if (!adSnap.exists) {
      sendJson(req, res, 404, { ok: false, error: 'AD_NOT_FOUND' });
      return;
    }
    const adData = adSnap.data()!;
    if (adData.status !== 'active') {
      sendJson(req, res, 403, { ok: false, error: 'AD_INACTIVE' });
      return;
    }
    if (adData.adType === 'direct_link') {
      sendJson(req, res, 403, { ok: false, error: 'S2S_POSTBACK_REQUIRED_FOR_DIRECT_LINK' });
      return;
    }
    if (adData.rewardVerificationMethod !== 'sdk_callback') {
      sendJson(req, res, 403, { ok: false, error: 'S2S_POSTBACK_REQUIRED' });
      return;
    }

    const adNetworkLower = String(adData.adNetwork || '').toLowerCase();
    const configuredPlacement = String(adData.placementOrUrl || '').trim();
    if (adNetworkLower.includes('applixir') || /^applixir:/i.test(configuredPlacement)) {
      sendJson(req, res, 403, { ok: false, error: 'S2S_POSTBACK_REQUIRED' });
      return;
    }
    if (adNetworkLower.includes('monetag') && platformContext !== 'telegram_mini_app') {
      sendJson(req, res, 403, { ok: false, error: 'MONETAG_SDK_REQUIRES_TELEGRAM_MINI_APP' });
      return;
    }

    const configuredGamUnit = configuredPlacement.replace(/^gam:/i, '').trim();
    const isGamPath =
      platformContext === 'web_gpt' &&
      /^\/\d{4,15}\/[a-zA-Z0-9_.\-/]{1,120}$/.test(configuredGamUnit) &&
      configuredGamUnit === sdkZoneId;
    const numericPlacementMatch = configuredPlacement.match(/(\d{4,15})/);
    const isNumericMatch = Boolean(numericPlacementMatch && numericPlacementMatch[1] === sdkZoneId);

    if (!isGamPath && !isNumericMatch) {
      sendJson(req, res, 403, { ok: false, error: 'SDK_ZONE_MISMATCH' });
      return;
    }

    const requiredDurationSec = normalizeAdDurationSeconds(adData.estimatedDuration);
    const createdAtMs = toMillis(sessionData.createdAt);
    const elapsedSec = createdAtMs > 0 ? (Date.now() - createdAtMs) / 1000 : 0;

    if (elapsedSec < requiredDurationSec || watchedSeconds < requiredDurationSec) {
      sendJson(req, res, 409, {
        ok: false,
        error: 'ABNORMALLY_FAST_AD_COMPLETION',
        requiredDurationSec,
        elapsedSec: Math.floor(elapsedSec),
      });
      return;
    }

    const providerTxId = sanitizeId(`sdk_${sessionId}`);
    const outcome = await executeVerifiedAdRewardTransactionAdmin(ctx, {
      sessionId,
      userId: uid,
      adId,
      providerTxId,
      verificationSource: 'SDK Callback',
    });

    const dhakaToday = getDhakaDateKey();
    const networkName = String(adData.adNetwork || 'Monetag');
    const networkId = networkName.toLowerCase().includes('monetag')
      ? 'monetag'
      : sanitizeId(networkName.toLowerCase());
    const callbackId = sanitizeId(`cb_sdk_${sessionId}`);

    await Promise.all([
      ctx.db.collection('adCallbacks').doc(callbackId).set({
        callbackId,
        eventId: providerTxId,
        networkId,
        campaignId: '',
        sessionId,
        userId: uid,
        status: 'processed',
        signatureValid: true,
        timestampValid: true,
        replayDetected: false,
        rewardPoints: outcome.rewardPoints,
        rejectionReason: '',
        callbackTimestampSec: Math.floor(Date.now() / 1000),
        createdAt: FieldValue.serverTimestamp(),
      }),
      recordAdAnalyticsDeltaAdmin(ctx, {
        networkId,
        networkName,
        dhakaDate: dhakaToday,
        clicksSupported: false,
        deltaImpressions: 1,
        deltaVerified: 1,
        deltaRewards: outcome.rewardPoints,
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId,
        actorUid: uid,
        eventType: 'sdk_callback_processed',
        severity: 'info',
        status: 'processed',
        details: `Verified Rewarded SDK completion (zone=${sdkZoneId}, ${Math.floor(elapsedSec)}s) for user=${uid}, +${outcome.rewardPoints} Pts`,
      }),
      processReferralQualificationAdmin(ctx, uid),
      writeSecurityAuditLogAdmin(ctx, {
        userId: uid,
        eventType: 'ad_reward_credited',
        category: 'ad_reward',
        severity: 'info',
        transactionId: outcome.txId,
        details: `Verified SDK callback credited +${outcome.rewardPoints} Pts for ad ${adId} (session ${sessionId})`,
      }),
    ]);

    sendJson(req, res, 200, { ok: true, ...outcome });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(req, res);
      return;
    }
    const code = err instanceof Error ? err.message : 'SDK_VERIFICATION_FAILED';
    const statusCode =
      code === 'DUPLICATE_PROVIDER_TX' ||
      code === 'SESSION_ALREADY_FINALIZED' ||
      code === 'ABNORMALLY_FAST_AD_COMPLETION'
        ? 409
        : code === 'GLOBAL_DAILY_LIMIT_REACHED' ||
            code === 'PER_AD_DAILY_LIMIT_REACHED' ||
            code === 'RATE_LIMIT_EXCEEDED'
          ? 429
          : 400;
    sendJson(req, res, statusCode, { ok: false, error: code });
  }
}
