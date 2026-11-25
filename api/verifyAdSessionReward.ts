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

const TERMINAL_REJECTION_REASONS = new Set([
  'MONETAG_EVENT_NON_VALUED',
  'MONETAG_EVENT_NOT_VALUED',
  'APPLIXIR_STATUS_NOT_COMPLETED',
  'NETWORK_DISABLED',
  'NETWORK_REWARD_NOT_ELIGIBLE',
  'CAMPAIGN_DISABLED',
  'CAMPAIGN_REWARD_INELIGIBLE',
  'CAMPAIGN_GLOBAL_DAILY_LIMIT_REACHED',
  'USER_NOT_ACTIVE',
  'GLOBAL_DAILY_LIMIT_REACHED',
  'PER_AD_DAILY_LIMIT_REACHED',
  'DAILY_BONUS_ALREADY_CLAIMED',
  'INCENTIVIZED_TRAFFIC_DISALLOWED',
]);

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
  if (!sessionId || !String(body.sessionId || '').trim()) {
    sendJson(req, res, 400, { ok: false, error: 'Missing sessionId' });
    return;
  }

  try {
    const verifyRate = await enforceRateLimitAdmin(ctx, {
      bucketKey: `ad_verify_${uid}`,
      actionName: 'verifyAdSessionReward',
      actorId: uid,
      maxRequests: 40,
      windowSeconds: 60,
    });
    if (!verifyRate.allowed) {
      sendJson(req, res, 429, {
        ok: false,
        error: 'RATE_LIMIT_EXCEEDED',
        retryAfterSec: verifyRate.retryAfterSec,
      });
      return;
    }

    const sessionRef = ctx.db.collection('adSessions').doc(sessionId);
    const sessionSnap = await sessionRef.get();
    if (!sessionSnap.exists) {
      sendJson(req, res, 404, { ok: false, error: 'SESSION_NOT_FOUND' });
      return;
    }

    const sessionData = sessionSnap.data()!;
    if (sessionData.userId !== uid) {
      sendJson(req, res, 403, { ok: false, error: 'SESSION_MISMATCH' });
      return;
    }

    if (sessionData.status === 'completed') {
      const txId = String(sessionData.transactionId || sessionId);
      let rewardPoints = Number(sessionData.expectedRewardPoints || 0);
      if (txId) {
        const txSnap = await ctx.db.collection('transactions').doc(txId).get().catch(() => null);
        if (txSnap && txSnap.exists) {
          rewardPoints = Number(txSnap.data()?.points ?? txSnap.data()?.pointsDelta ?? rewardPoints);
        }
      }
      sendJson(req, res, 200, {
        ok: true,
        status: 'completed',
        rewardPoints,
        txId,
      });
      return;
    }

    if (sessionData.status === 'rejected') {
      sendJson(req, res, 409, {
        ok: false,
        status: 'rejected',
        error: String(sessionData.rejectionReason || 'SESSION_REJECTED'),
      });
      return;
    }

    const adId = String(sessionData.adId || '');
    const isDailyBonus = adId === DAILY_CHECKIN_BONUS_AD_ID;
    let adOrBonusSnap = await ctx.db
      .collection(isDailyBonus ? 'appSettings' : 'advertisements')
      .doc(isDailyBonus ? 'dailyBonus' : adId)
      .get();

    if (!isDailyBonus && !adOrBonusSnap.exists) {
      const dlSnap = await ctx.db.collection('directLinkAds').doc(adId).get().catch(() => null);
      if (dlSnap && dlSnap.exists) {
        adOrBonusSnap = dlSnap;
      }
    }

    if (!adOrBonusSnap.exists) {
      sendJson(req, res, isDailyBonus ? 412 : 404, {
        ok: false,
        status: 'rejected',
        error: isDailyBonus ? 'DAILY_BONUS_NOT_CONFIGURED' : 'AD_NOT_FOUND',
      });
      return;
    }

    const adOrBonusData = adOrBonusSnap.data()!;
    const requiredDurationSec = normalizeAdDurationSeconds(
      isDailyBonus ? adOrBonusData.durationSeconds : adOrBonusData.estimatedDuration,
    );

    const createdAtMs = toMillis(sessionData.createdAt);
    const elapsedSec = createdAtMs > 0 ? (Date.now() - createdAtMs) / 1000 : 0;

    if (elapsedSec < requiredDurationSec) {
      sendJson(req, res, 200, {
        ok: true,
        status: 'awaiting_timer',
        remainingSec: Math.max(1, Math.ceil(requiredDurationSec - elapsedSec)),
        elapsedSec: Math.floor(elapsedSec),
        requiredDurationSec,
      });
      return;
    }

    // Look up callbacks already received for this sessionId (held or rejected)
    const callbacksSnap = await ctx.db
      .collection('adCallbacks')
      .where('sessionId', '==', sessionId)
      .limit(20)
      .get();

    const callbackDocs = callbacksSnap.docs.map((d) => ({
      ref: d.ref,
      data: d.data(),
    }));

    // 1. Release held S2S callback once >= 30s server clock elapsed
    const heldCallback = callbackDocs.find(
      (c) =>
        c.data.status === 'awaiting_duration' &&
        c.data.signatureValid === true &&
        c.data.timestampValid === true,
    );

    if (heldCallback) {
      const cbData = heldCallback.data;
      const providerTxId = sanitizeId(
        String(cbData.providerTxId || cbData.eventId || `cb_${sessionId}`),
      );
      const networkId = String(cbData.networkId || 'monetag');
      const dhakaToday = getDhakaDateKey();
      const networkName = String(sessionData.adNetwork || 'Partner Network');

      try {
        const outcome = await executeVerifiedAdRewardTransactionAdmin(ctx, {
          sessionId,
          userId: uid,
          adId,
          providerTxId,
          verificationSource: 'S2S Postback',
        });

        await Promise.all([
          heldCallback.ref.update({
            status: 'processed',
            rewardPoints: outcome.rewardPoints,
            rejectionReason: '',
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
            eventType: 'callback_processed',
            severity: 'info',
            status: 'processed',
            details: `Released held S2S callback for user=${uid}, ad=${adId}, session=${sessionId}, +${outcome.rewardPoints} Pts`,
          }),
          networkId
            ? ctx.db
                .collection('adNetworks')
                .doc(networkId)
                .update({
                  healthStatus: 'connected',
                  healthMessage: `Live S2S callback verified (${dhakaToday}).`,
                  updatedAt: FieldValue.serverTimestamp(),
                })
                .catch(() => {})
            : Promise.resolve(),
          processReferralQualificationAdmin(ctx, uid),
          writeSecurityAuditLogAdmin(ctx, {
            userId: uid,
            eventType: 'ad_reward_credited',
            category: 'ad_reward',
            severity: 'info',
            transactionId: outcome.txId,
            details: `Verified held S2S callback credited +${outcome.rewardPoints} Pts for ad ${adId} (session ${sessionId})`,
          }),
        ]);

        sendJson(req, res, 200, {
          ok: true,
          status: 'completed',
          rewardPoints: outcome.rewardPoints,
          txId: outcome.txId,
        });
        return;
      } catch (releaseErr) {
        const releaseCode = releaseErr instanceof Error ? releaseErr.message : 'UNKNOWN_ERROR';
        if (releaseCode === 'DUPLICATE_PROVIDER_TX' || releaseCode === 'SESSION_ALREADY_FINALIZED') {
          const latestSnap = await sessionRef.get();
          const latestData = latestSnap.exists ? latestSnap.data()! : null;
          if (latestData && latestData.status === 'completed') {
            sendJson(req, res, 200, {
              ok: true,
              status: 'completed',
              rewardPoints: Number(latestData.expectedRewardPoints || 0),
              txId: String(latestData.transactionId || sessionId),
            });
            return;
          }
        }
        sendJson(req, res, 409, {
          ok: false,
          status: 'rejected',
          error: releaseCode,
        });
        return;
      }
    }

    // 2. Surface definitive provider/policy rejections immediately (e.g. Monetag non_valued)
    const rejectedCallbacks = callbackDocs
      .filter((c) => c.data.status !== 'processed' && c.data.status !== 'awaiting_duration')
      .sort((a, b) => toMillis(b.data.createdAt) - toMillis(a.data.createdAt));

    const latestRejected = rejectedCallbacks[0];
    const lastCallbackError = latestRejected
      ? String(latestRejected.data.rejectionReason || latestRejected.data.status || '')
      : '';

    if (lastCallbackError && TERMINAL_REJECTION_REASONS.has(lastCallbackError)) {
      sendJson(req, res, 409, {
        ok: false,
        status: 'rejected',
        error: lastCallbackError,
        lastCallbackError,
      });
      return;
    }

    const adNetworkName = isDailyBonus
      ? 'Monetag'
      : String(adOrBonusData.adNetwork || sessionData.adNetwork || 'Monetag');
    const placementVal = isDailyBonus
      ? String(adOrBonusData.monetagDirectLinkUrl || '')
      : String(adOrBonusData.placementOrUrl || adOrBonusData.url || '');
    const adNetLower = adNetworkName.toLowerCase();
    const isAppLixir = adNetLower.includes('applixir') || /^applixir:/i.test(placementVal.trim());
    const isMonetag = adNetLower.includes('monetag');
    const strictMonetagS2S = process.env.REQUIRE_MONETAG_S2S_POSTBACK === 'true';
    const requiresS2SPostback =
      isAppLixir ||
      (strictMonetagS2S &&
        (isMonetag ||
          isDailyBonus ||
          adOrBonusData.rewardVerificationMethod === 's2s_postback' ||
          adOrBonusData.adType === 'direct_link'));

    // AppLixir (or strict S2S mode when enabled) waits for verified backend S2S Postback
    if (requiresS2SPostback) {
      sendJson(req, res, 200, {
        ok: true,
        status: 'pending',
        callbackArrived: false,
        elapsedSec: Math.floor(elapsedSec),
        requiredDurationSec,
        ...(lastCallbackError ? { lastCallbackError } : {}),
      });
      return;
    }

    // 3. Verified 30s+ Direct Link / Daily Check-in Bonus / Web session
    const verifiedTxId = sanitizeId(`timer_${sessionId}`);
    const networkId = isMonetag ? 'monetag' : sanitizeId(adNetLower || 'direct_link');
    const dhakaToday = getDhakaDateKey();

    try {
      const outcome = await executeVerifiedAdRewardTransactionAdmin(ctx, {
        sessionId,
        userId: uid,
        adId,
        providerTxId: verifiedTxId,
        verificationSource: 'Verified Session',
      });

      await Promise.all([
        recordAdAnalyticsDeltaAdmin(ctx, {
          networkId,
          networkName: adNetworkName,
          dhakaDate: dhakaToday,
          clicksSupported: false,
          deltaImpressions: 1,
          deltaVerified: 1,
          deltaRewards: outcome.rewardPoints,
        }),
        writeAdNetworkLogAdmin(ctx, {
          networkId,
          actorUid: uid,
          eventType: 'timer_session_completed',
          severity: 'info',
          status: 'processed',
          details: `Verified ${Math.floor(elapsedSec)}s ad viewing completion for user=${uid}, ad=${adId}, session=${sessionId}, +${outcome.rewardPoints} Pts`,
        }),
        processReferralQualificationAdmin(ctx, uid),
        writeSecurityAuditLogAdmin(ctx, {
          userId: uid,
          eventType: 'ad_reward_credited',
          category: 'ad_reward',
          severity: 'info',
          transactionId: outcome.txId,
          details: `Verified ${Math.floor(elapsedSec)}s viewing session credited +${outcome.rewardPoints} Pts for ad ${adId} (session ${sessionId})`,
        }),
      ]);

      sendJson(req, res, 200, {
        ok: true,
        status: 'completed',
        rewardPoints: outcome.rewardPoints,
        txId: outcome.txId,
      });
    } catch (creditErr) {
      const creditCode = creditErr instanceof Error ? creditErr.message : 'UNKNOWN_ERROR';
      if (creditCode === 'DUPLICATE_PROVIDER_TX' || creditCode === 'SESSION_ALREADY_FINALIZED') {
        const latestSnap = await sessionRef.get();
        const latestData = latestSnap.exists ? latestSnap.data()! : null;
        if (latestData && latestData.status === 'completed') {
          sendJson(req, res, 200, {
            ok: true,
            status: 'completed',
            rewardPoints: Number(latestData.expectedRewardPoints || 0),
            txId: String(latestData.transactionId || sessionId),
          });
          return;
        }
      }
      sendJson(req, res, 409, {
        ok: false,
        status: 'rejected',
        error: creditCode,
      });
    }
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
      error: err instanceof Error ? err.message : 'SESSION_VERIFICATION_FAILED',
    });
  }
}
