import type { ServerResponse } from 'node:http';
import {
  type ApiRequest,
  applyCors,
  buildSetWrite,
  createFirestoreContext,
  DAILY_CHECKIN_BONUS_AD_ID,
  DEFAULT_GLOBAL_DAILY_AD_LIMIT,
  fsBeginTransaction,
  fsCommit,
  fsGetDoc,
  fsQueryEq,
  fsRollback,
  getDhakaDateKey,
  getDhakaYesterdayDateKey,
  MIN_SECONDS_BETWEEN_COMPLETIONS,
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
  const sessionId = sanitizeId(String(body.sessionId || '').trim());
  if (!sessionId) {
    sendJson(res, 400, { ok: false, error: 'Missing sessionId' });
    return;
  }

  const uid = authCheck.auth.uid;

  try {
    const sessionSnap = await fsGetDoc(ctx, `adSessions/${sessionId}`);
    if (!sessionSnap.exists) {
      sendJson(res, 404, { ok: false, error: 'SESSION_NOT_FOUND' });
      return;
    }

    const sessionData = sessionSnap.data;
    if (sessionData.userId !== uid) {
      sendJson(res, 403, { ok: false, error: 'SESSION_MISMATCH' });
      return;
    }

    if (sessionData.status === 'completed') {
      const txId = String(sessionData.transactionId || sessionId);
      let rewardPoints = Number(sessionData.expectedRewardPoints || 0);
      if (txId) {
        const txSnap = await fsGetDoc(ctx, `transactions/${txId}`).catch(
          (): { exists: boolean; data: Record<string, unknown> } => ({
            exists: false,
            data: {},
          }),
        );
        if (txSnap.exists) {
          rewardPoints = Number(txSnap.data.points ?? txSnap.data.pointsDelta ?? rewardPoints);
        }
      }
      sendJson(res, 200, {
        ok: true,
        status: 'completed',
        rewardPoints,
        txId,
      });
      return;
    }

    if (sessionData.status === 'rejected') {
      sendJson(res, 409, {
        ok: false,
        status: 'rejected',
        error: String(sessionData.rejectionReason || 'SESSION_REJECTED'),
      });
      return;
    }

    const adId = String(sessionData.adId || '');
    const isDailyBonus = adId === DAILY_CHECKIN_BONUS_AD_ID;
    const adOrBonusSnap = await fsGetDoc(
      ctx,
      isDailyBonus ? 'appSettings/dailyBonus' : `advertisements/${adId}`,
    );

    if (!adOrBonusSnap.exists) {
      sendJson(res, isDailyBonus ? 412 : 404, {
        ok: false,
        status: 'rejected',
        error: isDailyBonus ? 'DAILY_BONUS_NOT_CONFIGURED' : 'AD_NOT_FOUND',
      });
      return;
    }

    const adOrBonusData = adOrBonusSnap.data;
    const requiredDurationSec = normalizeAdDurationSeconds(
      isDailyBonus ? adOrBonusData.durationSeconds : adOrBonusData.estimatedDuration,
    );

    const createdAtMs = Number(sessionData.createdAt || 0);
    const elapsedSec = createdAtMs > 0 ? (Date.now() - createdAtMs) / 1000 : 0;

    if (elapsedSec < requiredDurationSec) {
      sendJson(res, 200, {
        ok: true,
        status: 'awaiting_timer',
        remainingSec: Math.max(1, Math.ceil(requiredDurationSec - elapsedSec)),
        elapsedSec: Math.floor(elapsedSec),
        requiredDurationSec,
      });
      return;
    }

    const adNetworkName = isDailyBonus
      ? 'Monetag'
      : String(adOrBonusData.adNetwork || sessionData.adNetwork || 'Monetag');
    const placementVal = isDailyBonus
      ? String(adOrBonusData.monetagDirectLinkUrl || '')
      : String(adOrBonusData.placementOrUrl || '');
    const isAppLixir =
      adNetworkName.toLowerCase().includes('applixir') || /^applixir:/i.test(placementVal.trim());

    if (isAppLixir) {
      const callbacks = await fsQueryEq(ctx, 'adCallbacks', 'sessionId', sessionId, 20);
      const held = callbacks.find(
        (c) =>
          c.data.status === 'awaiting_duration' &&
          c.data.signatureValid === true &&
          c.data.timestampValid === true,
      );
      if (!held) {
        sendJson(res, 200, {
          ok: true,
          status: 'pending',
          callbackArrived: false,
          elapsedSec: Math.floor(elapsedSec),
          requiredDurationSec,
        });
        return;
      }
    }

    const dhakaToday = getDhakaDateKey();
    const providerTxId = sanitizeId(`timer_${sessionId}`);
    const completionId = sanitizeId(`comp_${providerTxId}`);
    const txId = sanitizeId(`tx_${providerTxId}`);
    const ledgerId = sanitizeId(`led_${txId}`);

    const tx = await fsBeginTransaction(ctx);
    try {
      const [
        completionSnap,
        txSessionSnap,
        userSnap,
        walletSnap,
        txAdOrBonusSnap,
        dailyOrBonusUserSnap,
        txDocSnap,
        walletSettingsSnap,
        economySnap,
      ] = await Promise.all([
        fsGetDoc(ctx, `adCompletions/${completionId}`, tx),
        fsGetDoc(ctx, `adSessions/${sessionId}`, tx),
        fsGetDoc(ctx, `users/${uid}`, tx),
        fsGetDoc(ctx, `wallets/${uid}`, tx),
        fsGetDoc(ctx, isDailyBonus ? 'appSettings/dailyBonus' : `advertisements/${adId}`, tx),
        fsGetDoc(ctx, isDailyBonus ? `dailyBonuses/${uid}` : `dailyAdLimits/${uid}_${dhakaToday}`, tx),
        fsGetDoc(ctx, `transactions/${txId}`, tx),
        fsGetDoc(ctx, 'appSettings/wallet', tx),
        fsGetDoc(ctx, 'appConfig/economy', tx),
      ]);

      const earningEnabled =
        walletSettingsSnap.exists && typeof walletSettingsSnap.data.earningEnabled === 'boolean'
          ? Boolean(walletSettingsSnap.data.earningEnabled)
          : true;
      const dailyAdLimit = Math.max(
        1,
        Number(
          walletSettingsSnap.data.dailyAdLimit ??
            economySnap.data.dailyAdLimit ??
            DEFAULT_GLOBAL_DAILY_AD_LIMIT,
        ),
      );
      const rawPointsPerBdt =
        walletSettingsSnap.data.pointsPerBdt ?? economySnap.data.pointsPerBdt ?? null;
      const pointsPerBdt =
        typeof rawPointsPerBdt === 'number' && rawPointsPerBdt > 0 ? rawPointsPerBdt : null;
      const fallbackDailyBonusPoints = Number(
        walletSettingsSnap.data.dailyBonusPoints ?? economySnap.data.dailyBonusPoints ?? 0,
      );

      if (!earningEnabled) throw new Error('EARNING_DISABLED');
      if (completionSnap.exists || txDocSnap.exists) throw new Error('DUPLICATE_PROVIDER_TX');
      if (!txSessionSnap.exists) throw new Error('SESSION_NOT_FOUND');
      if (txSessionSnap.data.userId !== uid || txSessionSnap.data.adId !== adId) {
        throw new Error('SESSION_MISMATCH');
      }
      if (txSessionSnap.data.status !== 'pending') {
        throw new Error('SESSION_ALREADY_FINALIZED');
      }
      if (!userSnap.exists) throw new Error('USER_NOT_FOUND');
      const userData = userSnap.data;
      if (userData.accountStatus !== 'active') throw new Error('USER_NOT_ACTIVE');

      let rewardPoints = 0;
      let adName = 'Advertisement';
      let adNetwork = 'Partner Network';
      let nextStreakDays = 1;
      let currentCount = 0;
      let currentEarned = 0;
      let completedAdIds: string[] = [];

      if (isDailyBonus) {
        if (!txAdOrBonusSnap.exists) throw new Error('DAILY_BONUS_NOT_CONFIGURED');
        const bonusCfg = txAdOrBonusSnap.data;
        if (bonusCfg.enabled !== true) throw new Error('AD_INACTIVE');
        if (bonusCfg.incentivizedTrafficAllowed !== true) {
          throw new Error('INCENTIVIZED_TRAFFIC_DISALLOWED');
        }
        const prevBonus = dailyOrBonusUserSnap.exists ? dailyOrBonusUserSnap.data : {};
        const lastClaimDate = String(prevBonus.lastClaimDate || '');
        if (lastClaimDate === dhakaToday) {
          throw new Error('DAILY_BONUS_ALREADY_CLAIMED');
        }
        const yesterdayDhaka = getDhakaYesterdayDateKey(dhakaToday);
        const prevStreak = Math.max(0, Math.floor(Number(prevBonus.streakDays || 0)));
        nextStreakDays = lastClaimDate === yesterdayDhaka ? prevStreak + 1 : 1;

        rewardPoints = Math.max(
          0,
          Math.floor(Number(bonusCfg.rewardPoints || fallbackDailyBonusPoints || 0)),
        );
        if (rewardPoints <= 0) throw new Error('INVALID_REWARD_AMOUNT');
        adName = 'Daily Check-in Bonus';
        adNetwork = 'Monetag';
      } else {
        if (!txAdOrBonusSnap.exists) throw new Error('AD_NOT_FOUND');
        const adData = txAdOrBonusSnap.data;
        if (adData.status !== 'active') throw new Error('AD_INACTIVE');
        if (adData.rewardVerificationMethod === 'none') throw new Error('AD_VERIFICATION_DISABLED');
        if (adData.adType === 'direct_link' && adData.incentivizedTrafficAllowed !== true) {
          throw new Error('INCENTIVIZED_TRAFFIC_DISALLOWED');
        }

        const existingDaily = dailyOrBonusUserSnap.exists ? dailyOrBonusUserSnap.data : {};
        currentCount = Number(existingDaily.completedCount || 0);
        currentEarned = Number(existingDaily.earnedPoints || 0);
        completedAdIds = Array.isArray(existingDaily.completedAdIds)
          ? (existingDaily.completedAdIds as unknown[]).map((x) => String(x))
          : [];

        const lastUpdatedMs = Number(existingDaily.updatedAt || 0);
        if (lastUpdatedMs > 0 && (Date.now() - lastUpdatedMs) / 1000 < MIN_SECONDS_BETWEEN_COMPLETIONS) {
          throw new Error('RATE_LIMIT_EXCEEDED');
        }
        if (currentCount >= dailyAdLimit) throw new Error('GLOBAL_DAILY_LIMIT_REACHED');
        const perAdLimit = Math.max(1, Number(adData.dailyLimit || 1));
        if (completedAdIds.filter((id) => id === adId).length >= perAdLimit) {
          throw new Error('PER_AD_DAILY_LIMIT_REACHED');
        }
        rewardPoints = Math.max(0, Number(adData.rewardPoints || 0));
        if (rewardPoints <= 0) throw new Error('INVALID_REWARD_AMOUNT');
        adName = String(adData.adName || 'Advertisement');
        adNetwork = String(adData.adNetwork || 'Partner Network');
      }

      const w = walletSnap.exists ? walletSnap.data : {};
      const prevTotalPoints = Number(w.totalPoints ?? userData.points ?? 0);
      const prevReserved = Number(w.reservedPoints ?? 0);
      const prevAvailable = Number(w.availablePoints ?? Math.max(0, prevTotalPoints - prevReserved));
      const prevPending = Number(w.pendingPoints ?? 0);
      const prevTotalEarned = Number(w.totalEarnedPoints ?? userData.totalEarnings ?? 0);
      const prevWithdrawnPts = Number(w.totalWithdrawnPoints ?? 0);
      const prevWithdrawnBdt = Number(w.totalWithdrawnBdt ?? 0);

      const newTotalPoints = prevTotalPoints + rewardPoints;
      const newAvailablePoints = prevAvailable + rewardPoints;
      const rateUsed = pointsPerBdt ?? 0;
      const bdtSnapshot = pointsPerBdt ? Number((rewardPoints / pointsPerBdt).toFixed(2)) : 0;
      const description = isDailyBonus
        ? `Daily Check-in Bonus · Day ${nextStreakDays} Streak`
        : `${adNetwork} · Verified Session ${providerTxId}`;
      const txType = isDailyBonus ? 'daily_bonus' : 'ad_reward';

      const writes: Array<Record<string, unknown>> = [
        ...buildSetWrite(ctx, `adCompletions/${completionId}`, {
          completionId,
          providerTxId,
          sessionId,
          userId: uid,
          adId,
          adName,
          adNetwork,
          rewardPoints,
          transactionId: txId,
          dhakaDate: dhakaToday,
          status: 'completed',
          createdAt: SERVER_TIMESTAMP_SENTINEL,
        }),
        ...buildSetWrite(
          ctx,
          `adSessions/${sessionId}`,
          {
            status: 'completed',
            transactionId: txId,
            rejectionReason: '',
          },
          { mergeFields: ['status', 'transactionId', 'rejectionReason'] },
        ),
        ...(isDailyBonus
          ? buildSetWrite(ctx, `dailyBonuses/${uid}`, {
              uid,
              streakDays: nextStreakDays,
              lastClaimDate: dhakaToday,
              lastClaimPoints: rewardPoints,
              updatedAt: SERVER_TIMESTAMP_SENTINEL,
            })
          : buildSetWrite(ctx, `dailyAdLimits/${uid}_${dhakaToday}`, {
              userId: uid,
              dhakaDate: dhakaToday,
              completedCount: currentCount + 1,
              earnedPoints: currentEarned + rewardPoints,
              completedAdIds: [...completedAdIds, adId],
              updatedAt: SERVER_TIMESTAMP_SENTINEL,
            })),
        ...buildSetWrite(ctx, `transactions/${txId}`, {
          transactionId: txId,
          userId: uid,
          title: adName,
          subtitle: description,
          description,
          type: txType,
          direction: 'credit',
          pointsDelta: rewardPoints,
          points: rewardPoints,
          bdtAmount: pointsPerBdt ? bdtSnapshot : null,
          conversionRateUsed: pointsPerBdt ?? null,
          status: 'completed',
          createdAt: SERVER_TIMESTAMP_SENTINEL,
        }),
        ...buildSetWrite(ctx, `walletLedger/${ledgerId}`, {
          entryId: ledgerId,
          transactionId: txId,
          userId: uid,
          entryType: 'credit',
          transactionType: txType,
          pointsDelta: rewardPoints,
          bdtAmount: bdtSnapshot,
          conversionRateUsed: rateUsed,
          previousPoints: prevTotalPoints,
          newPoints: newTotalPoints,
          previousReservedPoints: prevReserved,
          newReservedPoints: prevReserved,
          status: 'completed',
          description,
          createdAt: SERVER_TIMESTAMP_SENTINEL,
        }),
        ...buildSetWrite(ctx, `wallets/${uid}`, {
          userId: uid,
          totalPoints: newTotalPoints,
          availablePoints: newAvailablePoints,
          pendingPoints: prevPending,
          reservedPoints: prevReserved,
          totalEarnedPoints: prevTotalEarned + rewardPoints,
          totalWithdrawnPoints: prevWithdrawnPts,
          totalWithdrawnBdt: prevWithdrawnBdt,
          updatedAt: SERVER_TIMESTAMP_SENTINEL,
        }),
        ...buildSetWrite(
          ctx,
          `users/${uid}`,
          isDailyBonus
            ? {
                points: newAvailablePoints,
                totalEarnings: prevTotalEarned + rewardPoints,
              }
            : {
                points: newAvailablePoints,
                totalEarnings: prevTotalEarned + rewardPoints,
                totalAdViews: Number(userData.totalAdViews || 0) + 1,
              },
          {
            mergeFields: isDailyBonus
              ? ['points', 'totalEarnings']
              : ['points', 'totalEarnings', 'totalAdViews'],
          },
        ),
      ];

      await fsCommit(ctx, writes, tx);
      sendJson(res, 200, {
        ok: true,
        status: 'completed',
        rewardPoints,
        txId,
      });
    } catch (txErr) {
      await fsRollback(ctx, tx);
      const code = txErr instanceof Error ? txErr.message : 'UNKNOWN_ERROR';
      if (code === 'DUPLICATE_PROVIDER_TX' || code === 'SESSION_ALREADY_FINALIZED') {
        const latest = await fsGetDoc(ctx, `adSessions/${sessionId}`);
        if (latest.exists && latest.data.status === 'completed') {
          sendJson(res, 200, {
            ok: true,
            status: 'completed',
            rewardPoints: Number(latest.data.expectedRewardPoints || 0),
            txId: String(latest.data.transactionId || sessionId),
          });
          return;
        }
      }
      sendJson(res, 409, {
        ok: false,
        status: 'rejected',
        error: code,
      });
    }
  } catch (err) {
    sendJson(res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'SESSION_VERIFICATION_FAILED',
    });
  }
}
