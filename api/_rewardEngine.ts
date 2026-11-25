import crypto from 'node:crypto';
import { FieldValue, type Transaction } from 'firebase-admin/firestore';
import {
  DAILY_CHECKIN_BONUS_AD_ID,
  DEFAULT_GLOBAL_DAILY_AD_LIMIT,
  type FirebaseAdminContext,
  getDhakaDateKey,
  getDhakaYesterdayDateKey,
  MIN_AD_VIEW_DURATION_SEC,
  MIN_SECONDS_BETWEEN_COMPLETIONS,
  normalizeAdDurationSeconds,
  sanitizeId,
  timingSafeEqualString,
  toMillis,
  verifyAppLixirMd5Signature,
  verifyCallbackSecretOrHmac,
} from './_firebaseAdmin.ts';

export const MAX_CALLBACK_AGE_SEC = 900;
export const MAX_FUTURE_SKEW_SEC = 60;

export interface ActiveAppSettings {
  pointsPerBdt: number | null;
  dailyBonusPoints: number | null;
  minimumWithdrawPoints: number | null;
  maximumWithdrawAmountBdt: number | null;
  dailyAdLimit: number;
  walletEnabled: boolean;
  earningEnabled: boolean;
}

export async function readActiveAppSettingsAdmin(
  ctx: FirebaseAdminContext,
  txn?: Transaction,
): Promise<ActiveAppSettings> {
  const walletSettingsRef = ctx.db.collection('appSettings').doc('wallet');
  const economyRef = ctx.db.collection('appConfig').doc('economy');

  const [settingsSnap, economySnap] = txn
    ? await Promise.all([txn.get(walletSettingsRef), txn.get(economyRef)])
    : await Promise.all([walletSettingsRef.get(), economyRef.get()]);

  const s = settingsSnap.exists ? settingsSnap.data()! : {};
  const e = economySnap.exists ? economySnap.data()! : {};

  const rawRate = s.pointsPerBdt ?? e.pointsPerBdt;
  const rawBonus = s.dailyBonusPoints ?? e.dailyBonusPoints;
  const rawMinWd = s.minimumWithdrawPoints ?? e.minimumWithdrawPoints;
  const rawMaxWd = s.maximumWithdrawAmountBdt;
  const rawDailyLimit = s.dailyAdLimit ?? e.dailyAdLimit;

  return {
    pointsPerBdt: typeof rawRate === 'number' && rawRate > 0 ? rawRate : null,
    dailyBonusPoints: typeof rawBonus === 'number' && rawBonus >= 1 ? Math.floor(rawBonus) : null,
    minimumWithdrawPoints:
      typeof rawMinWd === 'number' && rawMinWd >= 1 ? Math.floor(rawMinWd) : null,
    maximumWithdrawAmountBdt:
      typeof rawMaxWd === 'number' && rawMaxWd >= 1 ? Number(rawMaxWd) : null,
    dailyAdLimit:
      typeof rawDailyLimit === 'number' && rawDailyLimit >= 1
        ? Math.floor(rawDailyLimit)
        : DEFAULT_GLOBAL_DAILY_AD_LIMIT,
    walletEnabled: typeof s.walletEnabled === 'boolean' ? s.walletEnabled : true,
    earningEnabled: typeof s.earningEnabled === 'boolean' ? s.earningEnabled : true,
  };
}

export async function enforceRateLimitAdmin(
  ctx: FirebaseAdminContext,
  params: {
    bucketKey: string;
    actionName: string;
    actorId: string;
    maxRequests: number;
    windowSeconds: number;
  },
): Promise<{ allowed: boolean; count: number; retryAfterSec: number }> {
  const docId = sanitizeId(params.bucketKey);
  const ref = ctx.db.collection('rateLimits').doc(docId);
  const nowMs = Date.now();
  const windowMs = Math.max(1, params.windowSeconds) * 1000;

  return ctx.db.runTransaction(async (txn) => {
    const snap = await txn.get(ref);
    const prev = snap.exists ? snap.data()! : null;
    const prevWindowStart = prev ? toMillis(prev.windowStartAt) : 0;

    if (!prev || nowMs - prevWindowStart >= windowMs) {
      txn.set(ref, {
        bucketKey: docId,
        actionName: params.actionName.slice(0, 60),
        actorId: params.actorId.slice(0, 128),
        count: 1,
        windowStartAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { allowed: true, count: 1, retryAfterSec: 0 };
    }

    const nextCount = Number(prev.count || 0) + 1;
    const retryAfterSec = Math.max(1, Math.ceil((windowMs - (nowMs - prevWindowStart)) / 1000));
    txn.update(ref, {
      count: nextCount,
      updatedAt: FieldValue.serverTimestamp(),
    });

    if (nextCount > params.maxRequests) {
      return { allowed: false, count: nextCount, retryAfterSec };
    }
    return { allowed: true, count: nextCount, retryAfterSec: 0 };
  });
}

export async function writeAdNetworkLogAdmin(
  ctx: FirebaseAdminContext,
  params: {
    networkId: string;
    actorUid?: string;
    actorEmail?: string;
    eventType: string;
    severity: 'info' | 'warning' | 'error';
    status?: string;
    details: string;
  },
): Promise<void> {
  const logId = sanitizeId(`anl_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  await ctx.db
    .collection('adNetworkLogs')
    .doc(logId)
    .set({
      logId,
      networkId: String(params.networkId || 'unknown').slice(0, 64),
      ...(params.actorUid ? { actorUid: params.actorUid.slice(0, 128) } : {}),
      ...(params.actorEmail ? { actorEmail: params.actorEmail.slice(0, 120) } : {}),
      eventType: params.eventType.slice(0, 80),
      severity: params.severity,
      ...(params.status ? { status: params.status.slice(0, 40) } : {}),
      details: params.details.slice(0, 500),
      createdAt: FieldValue.serverTimestamp(),
    })
    .catch(() => {});
}

export async function writeSecurityAuditLogAdmin(
  ctx: FirebaseAdminContext,
  params: {
    userId: string;
    eventType: string;
    category: 'auth' | 'ad_reward' | 'withdrawal' | 'referral' | 'wallet' | 'admin';
    severity: 'info' | 'low' | 'medium' | 'high';
    transactionId?: string;
    details: string;
  },
): Promise<void> {
  const logId = sanitizeId(`sec_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`);
  await ctx.db
    .collection('securityAuditLogs')
    .doc(logId)
    .set({
      logId,
      userId: params.userId.slice(0, 128),
      eventType: params.eventType.slice(0, 80),
      category: params.category,
      severity: params.severity,
      ...(params.transactionId ? { transactionId: params.transactionId.slice(0, 120) } : {}),
      details: params.details.slice(0, 500),
      createdAt: FieldValue.serverTimestamp(),
    })
    .catch(() => {});
}

export async function recordAdAnalyticsDeltaAdmin(
  ctx: FirebaseAdminContext,
  params: {
    networkId: string;
    networkName: string;
    dhakaDate: string;
    clicksSupported: boolean;
    deltaImpressions?: number;
    deltaVerified?: number;
    deltaRejected?: number;
    deltaRewards?: number;
  },
): Promise<void> {
  const analyticsId = sanitizeId(`${params.networkId}_${params.dhakaDate}`);
  const ref = ctx.db.collection('adAnalytics').doc(analyticsId);

  await ctx.db
    .runTransaction(async (txn) => {
      const snap = await txn.get(ref);
      const prev = snap.exists ? snap.data()! : {};
      txn.set(
        ref,
        {
          analyticsId,
          networkId: params.networkId,
          networkName: params.networkName.slice(0, 80),
          dhakaDate: params.dhakaDate,
          impressions: Math.max(0, Number(prev.impressions || 0) + (params.deltaImpressions || 0)),
          clicks: prev.clicks ?? null,
          clicksSupported: Boolean(prev.clicksSupported ?? params.clicksSupported),
          verifiedCompletions: Math.max(
            0,
            Number(prev.verifiedCompletions || 0) + (params.deltaVerified || 0),
          ),
          rejectedCompletions: Math.max(
            0,
            Number(prev.rejectedCompletions || 0) + (params.deltaRejected || 0),
          ),
          totalRewardsDistributed: Math.max(
            0,
            Number(prev.totalRewardsDistributed || 0) + (params.deltaRewards || 0),
          ),
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
    })
    .catch(() => {});
}

export async function executeVerifiedAdRewardTransactionAdmin(
  ctx: FirebaseAdminContext,
  params: {
    sessionId: string;
    userId: string;
    adId: string;
    providerTxId: string;
    verificationSource?: string;
  },
): Promise<{ rewardPoints: number; txId: string; bdtSnapshot: number }> {
  const { sessionId, userId, adId, providerTxId } = params;
  const dhakaToday = getDhakaDateKey();
  const isDailyBonus = adId === DAILY_CHECKIN_BONUS_AD_ID;
  const completionId = sanitizeId(`comp_${providerTxId}`);
  const txId = sanitizeId(`tx_${providerTxId}`);
  const ledgerId = sanitizeId(`led_${txId}`);

  const sessionRef = ctx.db.collection('adSessions').doc(sessionId);
  const completionRef = ctx.db.collection('adCompletions').doc(completionId);
  const userRef = ctx.db.collection('users').doc(userId);
  const walletRef = ctx.db.collection('wallets').doc(userId);
  const ledgerRef = ctx.db.collection('walletLedger').doc(ledgerId);
  const adRef = ctx.db.collection('advertisements').doc(adId);
  const directLinkRef = ctx.db.collection('directLinkAds').doc(adId);
  const dailyLimitRef = ctx.db.collection('dailyAdLimits').doc(`${userId}_${dhakaToday}`);
  const dailyBonusConfigRef = ctx.db.collection('appSettings').doc('dailyBonus');
  const dailyBonusUserRef = ctx.db.collection('dailyBonuses').doc(userId);
  const transactionRef = ctx.db.collection('transactions').doc(txId);

  return ctx.db.runTransaction(async (txn) => {
    const [
      completionSnap,
      sessionSnap,
      userSnap,
      walletSnap,
      adOrBonusConfigSnap,
      directLinkSnap,
      dailyOrBonusUserSnap,
      txSnap,
      settings,
    ] = await Promise.all([
      txn.get(completionRef),
      txn.get(sessionRef),
      txn.get(userRef),
      txn.get(walletRef),
      txn.get(isDailyBonus ? dailyBonusConfigRef : adRef),
      isDailyBonus ? Promise.resolve(null) : txn.get(directLinkRef),
      txn.get(isDailyBonus ? dailyBonusUserRef : dailyLimitRef),
      txn.get(transactionRef),
      readActiveAppSettingsAdmin(ctx, txn),
    ]);

    if (!settings.earningEnabled) {
      throw new Error('EARNING_DISABLED');
    }
    if (completionSnap.exists || txSnap.exists) {
      throw new Error('DUPLICATE_PROVIDER_TX');
    }
    if (!sessionSnap.exists) {
      throw new Error('SESSION_NOT_FOUND');
    }
    const sessionData = sessionSnap.data()!;
    if (sessionData.userId !== userId || sessionData.adId !== adId) {
      throw new Error('SESSION_MISMATCH');
    }
    if (sessionData.status !== 'pending') {
      throw new Error('SESSION_ALREADY_FINALIZED');
    }

    const sessionCreatedAtMs = toMillis(sessionData.createdAt);
    if (!sessionCreatedAtMs) {
      throw new Error('INVALID_SESSION_TIMESTAMP');
    }

    if (!userSnap.exists) {
      throw new Error('USER_NOT_FOUND');
    }
    const userData = userSnap.data()!;
    if (userData.accountStatus !== 'active') {
      throw new Error('USER_NOT_ACTIVE');
    }

    let requiredDurationSec = MIN_AD_VIEW_DURATION_SEC;
    let rewardPoints = 0;
    let adName = 'Advertisement';
    let adNetwork = 'Partner Network';
    let nextStreakDays = 1;
    let currentCount = 0;
    let currentEarned = 0;
    let completedAdIds: string[] = [];

    if (isDailyBonus) {
      if (!adOrBonusConfigSnap.exists) {
        throw new Error('DAILY_BONUS_NOT_CONFIGURED');
      }
      const bonusCfg = adOrBonusConfigSnap.data()!;
      if (bonusCfg.enabled !== true) {
        throw new Error('AD_INACTIVE');
      }
      if (bonusCfg.incentivizedTrafficAllowed !== true) {
        throw new Error('INCENTIVIZED_TRAFFIC_DISALLOWED');
      }
      requiredDurationSec = normalizeAdDurationSeconds(bonusCfg.durationSeconds);
      const elapsedSinceStartSec = (Date.now() - sessionCreatedAtMs) / 1000;
      if (elapsedSinceStartSec < requiredDurationSec) {
        throw new Error('ABNORMALLY_FAST_AD_COMPLETION');
      }

      const prevBonus = dailyOrBonusUserSnap.exists ? dailyOrBonusUserSnap.data()! : {};
      const lastClaimDate = String(prevBonus.lastClaimDate || '');
      if (lastClaimDate === dhakaToday) {
        throw new Error('DAILY_BONUS_ALREADY_CLAIMED');
      }
      const yesterdayDhaka = getDhakaYesterdayDateKey(dhakaToday);
      const prevStreak = Math.max(0, Math.floor(Number(prevBonus.streakDays || 0)));
      nextStreakDays = lastClaimDate === yesterdayDhaka ? prevStreak + 1 : 1;

      rewardPoints = Math.max(
        0,
        Math.floor(Number(bonusCfg.rewardPoints || settings.dailyBonusPoints || 0)),
      );
      if (rewardPoints <= 0) {
        throw new Error('INVALID_REWARD_AMOUNT');
      }
      adName = 'Daily Check-in Bonus';
      adNetwork = 'Monetag';
    } else {
      const effectiveAdSnap = adOrBonusConfigSnap.exists
        ? adOrBonusConfigSnap
        : directLinkSnap && directLinkSnap.exists
          ? directLinkSnap
          : null;
      if (!effectiveAdSnap) {
        throw new Error('AD_NOT_FOUND');
      }
      const adData = effectiveAdSnap.data()!;
      const isDirectLinkDoc = !adOrBonusConfigSnap.exists;
      if (adData.status !== 'active') {
        throw new Error('AD_INACTIVE');
      }
      if (adData.rewardVerificationMethod === 'none') {
        throw new Error('AD_VERIFICATION_DISABLED');
      }
      if ((isDirectLinkDoc || adData.adType === 'direct_link') && adData.incentivizedTrafficAllowed !== true) {
        throw new Error('INCENTIVIZED_TRAFFIC_DISALLOWED');
      }

      requiredDurationSec = normalizeAdDurationSeconds(adData.estimatedDuration);
      const elapsedSinceStartSec = (Date.now() - sessionCreatedAtMs) / 1000;
      if (elapsedSinceStartSec < requiredDurationSec) {
        throw new Error('ABNORMALLY_FAST_AD_COMPLETION');
      }

      const existingDaily = dailyOrBonusUserSnap.exists ? dailyOrBonusUserSnap.data()! : null;
      currentCount = Number(existingDaily?.completedCount || 0);
      currentEarned = Number(existingDaily?.earnedPoints || 0);
      completedAdIds = Array.isArray(existingDaily?.completedAdIds)
        ? existingDaily!.completedAdIds.map((x: unknown) => String(x))
        : [];

      const lastUpdatedMs = toMillis(existingDaily?.updatedAt);
      if (lastUpdatedMs > 0 && (Date.now() - lastUpdatedMs) / 1000 < MIN_SECONDS_BETWEEN_COMPLETIONS) {
        throw new Error('RATE_LIMIT_EXCEEDED');
      }
      if (currentCount >= settings.dailyAdLimit) {
        throw new Error('GLOBAL_DAILY_LIMIT_REACHED');
      }
      const perAdLimit = Math.max(1, Number(adData.dailyLimit || 1));
      if (completedAdIds.filter((id) => id === adId).length >= perAdLimit) {
        throw new Error('PER_AD_DAILY_LIMIT_REACHED');
      }

      rewardPoints = Math.max(0, Number(adData.rewardPoints || 0));
      if (rewardPoints <= 0) {
        throw new Error('INVALID_REWARD_AMOUNT');
      }
      adName = String(adData.adName || adData.title || 'Advertisement');
      adNetwork = String(adData.adNetwork || 'Partner Network');
    }

    const w = walletSnap.exists ? walletSnap.data()! : {};
    const prevTotalPoints = Number(w.totalPoints ?? userData.points ?? 0);
    const prevReserved = Number(w.reservedPoints ?? 0);
    const prevAvailable = Number(
      w.availablePoints ?? Math.max(0, prevTotalPoints - prevReserved),
    );
    const prevPending = Number(w.pendingPoints ?? 0);
    const prevTotalEarned = Number(w.totalEarnedPoints ?? userData.totalEarnings ?? 0);
    const prevWithdrawnPts = Number(w.totalWithdrawnPoints ?? 0);
    const prevWithdrawnBdt = Number(w.totalWithdrawnBdt ?? 0);

    const newTotalPoints = prevTotalPoints + rewardPoints;
    const newAvailablePoints = prevAvailable + rewardPoints;
    const rateUsed = settings.pointsPerBdt ?? 0;
    const bdtSnapshot = settings.pointsPerBdt
      ? Number((rewardPoints / settings.pointsPerBdt).toFixed(2))
      : 0;
    const sourceTag = params.verificationSource || 'S2S Tx';
    const description = isDailyBonus
      ? `Daily Check-in Bonus · Day ${nextStreakDays} Streak`
      : `${adNetwork} · ${sourceTag} ${providerTxId}`;
    const txType = isDailyBonus ? 'daily_bonus' : 'ad_reward';
    const nowServer = FieldValue.serverTimestamp();

    txn.set(completionRef, {
      completionId,
      providerTxId,
      sessionId,
      userId,
      adId,
      adName,
      adNetwork,
      rewardPoints,
      transactionId: txId,
      dhakaDate: dhakaToday,
      status: 'completed',
      createdAt: nowServer,
    });

    txn.update(sessionRef, {
      status: 'completed',
      transactionId: txId,
      rejectionReason: '',
    });

    if (isDailyBonus) {
      txn.set(
        dailyBonusUserRef,
        {
          uid: userId,
          streakDays: nextStreakDays,
          lastClaimDate: dhakaToday,
          lastClaimPoints: rewardPoints,
          updatedAt: nowServer,
        },
        { merge: true },
      );
    } else {
      txn.set(
        dailyLimitRef,
        {
          userId,
          dhakaDate: dhakaToday,
          completedCount: currentCount + 1,
          earnedPoints: currentEarned + rewardPoints,
          completedAdIds: [...completedAdIds, adId],
          updatedAt: nowServer,
        },
        { merge: true },
      );
    }

    txn.set(transactionRef, {
      transactionId: txId,
      userId,
      title: adName,
      subtitle: description,
      description,
      type: txType,
      direction: 'credit',
      pointsDelta: rewardPoints,
      points: rewardPoints,
      bdtAmount: settings.pointsPerBdt ? bdtSnapshot : null,
      conversionRateUsed: settings.pointsPerBdt ?? null,
      status: 'completed',
      createdAt: nowServer,
    });

    txn.set(ledgerRef, {
      entryId: ledgerId,
      transactionId: txId,
      userId,
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
      createdAt: nowServer,
    });

    txn.set(walletRef, {
      userId,
      totalPoints: newTotalPoints,
      availablePoints: newAvailablePoints,
      pendingPoints: prevPending,
      reservedPoints: prevReserved,
      totalEarnedPoints: prevTotalEarned + rewardPoints,
      totalWithdrawnPoints: prevWithdrawnPts,
      totalWithdrawnBdt: prevWithdrawnBdt,
      lastTransactionId: txId,
      updatedAt: nowServer,
    });

    if (isDailyBonus) {
      txn.update(userRef, {
        points: newAvailablePoints,
        totalEarnings: prevTotalEarned + rewardPoints,
      });
    } else {
      txn.update(userRef, {
        points: newAvailablePoints,
        totalEarnings: prevTotalEarned + rewardPoints,
        totalAdViews: FieldValue.increment(1),
      });
    }

    return { rewardPoints, txId, bdtSnapshot };
  });
}

export async function processReferralQualificationAdmin(
  ctx: FirebaseAdminContext,
  referredUid: string,
): Promise<void> {
  try {
    const referralRef = ctx.db.collection('referrals').doc(referredUid);
    const rewardRef = ctx.db.collection('referralRewards').doc(referredUid);
    const refSettingsRef = ctx.db.collection('referralSettings').doc('config');
    const referredUserRef = ctx.db.collection('users').doc(referredUid);

    const [referralSnap, rewardSnap, refSettingsSnap, referredUserSnap] = await Promise.all([
      referralRef.get(),
      rewardRef.get(),
      refSettingsRef.get(),
      referredUserRef.get(),
    ]);

    if (!referralSnap.exists) return;
    const refData = referralSnap.data()!;
    const referrerUid = String(refData.referrerUid || '');
    if (
      rewardSnap.exists ||
      refData.rewardStatus === 'credited' ||
      refData.qualificationStatus === 'rewarded' ||
      refData.qualificationStatus === 'rejected'
    ) {
      return;
    }
    if (!referrerUid || referrerUid === referredUid) return;

    const rs = refSettingsSnap.exists ? refSettingsSnap.data()! : {};
    const referralEnabled = typeof rs.referralEnabled === 'boolean' ? rs.referralEnabled : true;
    if (!referralEnabled) return;

    const referrerBonusPoints =
      typeof rs.referrerBonusPoints === 'number' && rs.referrerBonusPoints > 0
        ? Math.floor(rs.referrerBonusPoints)
        : 0;
    const newUserBonusPoints =
      typeof rs.newUserBonusPoints === 'number' && rs.newUserBonusPoints > 0
        ? Math.floor(rs.newUserBonusPoints)
        : 0;
    if (referrerBonusPoints <= 0 && newUserBonusPoints <= 0) return;

    const minAds = Math.max(0, Number(rs.minimumQualificationAds ?? 1));
    const requireEmailVerified =
      typeof rs.requireEmailVerified === 'boolean' ? rs.requireEmailVerified : true;
    const requireActiveAccount =
      typeof rs.requireActiveAccount === 'boolean' ? rs.requireActiveAccount : true;

    if (!referredUserSnap.exists) return;
    const referredUserData = referredUserSnap.data()!;
    if (requireActiveAccount && referredUserData.accountStatus !== 'active') return;
    if (requireEmailVerified && referredUserData.emailVerified !== true) return;
    if (Number(referredUserData.totalAdViews || 0) < minAds) return;

    await ctx.db.runTransaction(async (txn) => {
      const [liveReferral, liveReward, referrerUserSnap, referrerWalletSnap, refUserWalletSnap, settings] =
        await Promise.all([
          txn.get(referralRef),
          txn.get(rewardRef),
          txn.get(ctx.db.collection('users').doc(referrerUid)),
          txn.get(ctx.db.collection('wallets').doc(referrerUid)),
          txn.get(ctx.db.collection('wallets').doc(referredUid)),
          readActiveAppSettingsAdmin(ctx, txn),
        ]);

      if (!liveReferral.exists || liveReward.exists) return;
      const lr = liveReferral.data()!;
      if (lr.rewardStatus === 'credited' || lr.qualificationStatus === 'rewarded') return;
      if (!referrerUserSnap.exists || referrerUserSnap.data()?.accountStatus !== 'active') return;

      const nowServer = FieldValue.serverTimestamp();
      const rateUsed = settings.pointsPerBdt ?? 0;

      if (referrerBonusPoints > 0) {
        const w = referrerWalletSnap.exists ? referrerWalletSnap.data()! : {};
        const u = referrerUserSnap.data()!;
        const prevTot = Number(w.totalPoints ?? u.points ?? 0);
        const prevRes = Number(w.reservedPoints ?? 0);
        const prevAvail = Number(w.availablePoints ?? Math.max(0, prevTot - prevRes));
        const prevEarned = Number(w.totalEarnedPoints ?? u.totalEarnings ?? 0);
        const txId = sanitizeId(`tx_ref_${referredUid}`);
        const ledId = sanitizeId(`led_${txId}`);
        const bdt = rateUsed > 0 ? Number((referrerBonusPoints / rateUsed).toFixed(2)) : 0;

        txn.set(ctx.db.collection('transactions').doc(txId), {
          transactionId: txId,
          userId: referrerUid,
          title: 'Referral Bonus',
          subtitle: 'Verified referral qualification bonus',
          description: `Referral bonus for inviting ${referredUid}`,
          type: 'referral_bonus',
          direction: 'credit',
          pointsDelta: referrerBonusPoints,
          points: referrerBonusPoints,
          bdtAmount: rateUsed > 0 ? bdt : null,
          conversionRateUsed: rateUsed > 0 ? rateUsed : null,
          status: 'completed',
          createdAt: nowServer,
        });
        txn.set(ctx.db.collection('walletLedger').doc(ledId), {
          entryId: ledId,
          transactionId: txId,
          userId: referrerUid,
          entryType: 'credit',
          transactionType: 'referral_bonus',
          pointsDelta: referrerBonusPoints,
          bdtAmount: bdt,
          conversionRateUsed: rateUsed,
          previousPoints: prevTot,
          newPoints: prevTot + referrerBonusPoints,
          previousReservedPoints: prevRes,
          newReservedPoints: prevRes,
          status: 'completed',
          description: `Referral bonus for ${referredUid}`,
          createdAt: nowServer,
        });
        txn.set(
          ctx.db.collection('wallets').doc(referrerUid),
          {
            userId: referrerUid,
            totalPoints: prevTot + referrerBonusPoints,
            availablePoints: prevAvail + referrerBonusPoints,
            pendingPoints: Number(w.pendingPoints ?? 0),
            reservedPoints: prevRes,
            totalEarnedPoints: prevEarned + referrerBonusPoints,
            totalWithdrawnPoints: Number(w.totalWithdrawnPoints ?? 0),
            totalWithdrawnBdt: Number(w.totalWithdrawnBdt ?? 0),
            updatedAt: nowServer,
          },
          { merge: true },
        );
        txn.update(ctx.db.collection('users').doc(referrerUid), {
          points: prevAvail + referrerBonusPoints,
          totalEarnings: prevEarned + referrerBonusPoints,
        });
      }

      if (newUserBonusPoints > 0) {
        const w = refUserWalletSnap.exists ? refUserWalletSnap.data()! : {};
        const prevTot = Number(w.totalPoints ?? referredUserData.points ?? 0);
        const prevRes = Number(w.reservedPoints ?? 0);
        const prevAvail = Number(w.availablePoints ?? Math.max(0, prevTot - prevRes));
        const prevEarned = Number(w.totalEarnedPoints ?? referredUserData.totalEarnings ?? 0);
        const txId = sanitizeId(`tx_ref_new_${referredUid}`);
        const ledId = sanitizeId(`led_${txId}`);
        const bdt = rateUsed > 0 ? Number((newUserBonusPoints / rateUsed).toFixed(2)) : 0;

        txn.set(ctx.db.collection('transactions').doc(txId), {
          transactionId: txId,
          userId: referredUid,
          title: 'Welcome Referral Bonus',
          subtitle: 'Verified referral welcome bonus',
          description: `Welcome referral bonus (invited by ${referrerUid})`,
          type: 'referral_bonus',
          direction: 'credit',
          pointsDelta: newUserBonusPoints,
          points: newUserBonusPoints,
          bdtAmount: rateUsed > 0 ? bdt : null,
          conversionRateUsed: rateUsed > 0 ? rateUsed : null,
          status: 'completed',
          createdAt: nowServer,
        });
        txn.set(ctx.db.collection('walletLedger').doc(ledId), {
          entryId: ledId,
          transactionId: txId,
          userId: referredUid,
          entryType: 'credit',
          transactionType: 'referral_bonus',
          pointsDelta: newUserBonusPoints,
          bdtAmount: bdt,
          conversionRateUsed: rateUsed,
          previousPoints: prevTot,
          newPoints: prevTot + newUserBonusPoints,
          previousReservedPoints: prevRes,
          newReservedPoints: prevRes,
          status: 'completed',
          description: `Welcome referral bonus (${referrerUid})`,
          createdAt: nowServer,
        });
        txn.set(
          ctx.db.collection('wallets').doc(referredUid),
          {
            userId: referredUid,
            totalPoints: prevTot + newUserBonusPoints,
            availablePoints: prevAvail + newUserBonusPoints,
            pendingPoints: Number(w.pendingPoints ?? 0),
            reservedPoints: prevRes,
            totalEarnedPoints: prevEarned + newUserBonusPoints,
            totalWithdrawnPoints: Number(w.totalWithdrawnPoints ?? 0),
            totalWithdrawnBdt: Number(w.totalWithdrawnBdt ?? 0),
            updatedAt: nowServer,
          },
          { merge: true },
        );
        txn.update(referredUserRef, {
          points: prevAvail + newUserBonusPoints,
          totalEarnings: prevEarned + newUserBonusPoints,
        });
      }

      txn.set(rewardRef, {
        rewardId: referredUid,
        referralId: referredUid,
        referrerUid,
        referredUid,
        rewardPoints: referrerBonusPoints,
        newUserBonusPoints,
        status: 'credited',
        creditedAt: nowServer,
      });

      txn.update(referralRef, {
        qualificationStatus: 'rewarded',
        rewardStatus: 'credited',
        rewardPoints: referrerBonusPoints,
        newUserBonusPoints,
        qualifiedAt: nowServer,
        rewardedAt: nowServer,
      });
    });
  } catch {
    // Non-blocking referral qualification helper
  }
}

export function parseCallbackTimestampSec(raw: unknown): number | null {
  if (raw === undefined || raw === null || raw === '') return null;
  const num = Number(raw);
  if (!Number.isFinite(num) || num <= 0) return null;
  return num > 1_000_000_000_000 ? Math.floor(num / 1000) : Math.floor(num);
}

export function validateCallbackTimestamp(
  tsSec: number | null,
  nowSec: number = Math.floor(Date.now() / 1000),
): { valid: boolean; reason?: string } {
  if (tsSec === null) return { valid: true };
  const age = nowSec - tsSec;
  if (age > MAX_CALLBACK_AGE_SEC) {
    return { valid: false, reason: `EXPIRED_CALLBACK (age=${age}s > ${MAX_CALLBACK_AGE_SEC}s)` };
  }
  if (tsSec - nowSec > MAX_FUTURE_SKEW_SEC) {
    return { valid: false, reason: `INVALID_FUTURE_TIMESTAMP (+${tsSec - nowSec}s)` };
  }
  return { valid: true };
}

export interface NetworkCallbackInput {
  sessionId: string;
  userId: string;
  adId: string;
  providerTxId: string;
  eventId: string;
  networkId: string;
  campaignId: string;
  providedSecret: string;
  providedSignature: string;
  rawTimestamp: unknown;
  clientIp: string;
  applixirParams?: {
    gameApiKey: string;
    gameId: string;
    rawUserId: string;
    tid: string;
    status: string;
    signature: string;
    secretKeyParam: string;
  };
  monetagParams?: {
    rewardEventType: string;
    estimatedPrice?: string;
    zoneId?: string;
  };
}

export async function processVerifiedNetworkCallbackAdmin(
  ctx: FirebaseAdminContext,
  input: NetworkCallbackInput,
): Promise<{ httpStatus: number; body: Record<string, unknown> }> {
  const dhakaToday = getDhakaDateKey();
  const effectiveEventId = sanitizeId(input.eventId || input.providerTxId || `evt_${Date.now()}`);
  const callbackId = sanitizeId(`cb_${effectiveEventId}`);
  const callbackRef = ctx.db.collection('adCallbacks').doc(callbackId);

  let resolvedNetworkId = input.networkId ? sanitizeId(input.networkId) : '';
  if (
    !resolvedNetworkId &&
    input.applixirParams &&
    (input.applixirParams.gameApiKey ||
      input.applixirParams.gameId ||
      input.applixirParams.tid ||
      input.applixirParams.signature)
  ) {
    resolvedNetworkId = 'applixir';
  }

  let campaignData: FirebaseFirestore.DocumentData | null = null;
  let networkData: FirebaseFirestore.DocumentData | null = null;

  if (input.campaignId) {
    const campSnap = await ctx.db
      .collection('adCampaigns')
      .doc(sanitizeId(input.campaignId))
      .get();
    if (campSnap.exists) {
      campaignData = campSnap.data()!;
      if (!resolvedNetworkId && campaignData.networkId) {
        resolvedNetworkId = sanitizeId(String(campaignData.networkId));
      }
    }
  }

  let expectedNetworkSecret = '';
  let storedNetworkApiKey = '';
  if (resolvedNetworkId) {
    const [netSnap, secSnap] = await Promise.all([
      ctx.db.collection('adNetworks').doc(resolvedNetworkId).get(),
      ctx.db.collection('adNetworkSecrets').doc(resolvedNetworkId).get(),
    ]);
    if (netSnap.exists) networkData = netSnap.data()!;
    if (secSnap.exists) {
      const secData = secSnap.data()!;
      if (typeof secData.callbackSecret === 'string') {
        expectedNetworkSecret = String(secData.callbackSecret).trim();
      }
      if (typeof secData.apiKey === 'string') {
        storedNetworkApiKey = String(secData.apiKey).trim();
      }
    }
  }

  const envFallbackSecret = (
    (resolvedNetworkId === 'monetag' ? process.env.MONETAG_POSTBACK_SECRET : '') ||
    process.env.POSTBACK_SECRET ||
    ''
  ).trim();
  const envAppLixirSecret = (process.env.APPLIXIR_SECRET_KEY || '').trim();
  const envAppLixirApiKey = (process.env.APPLIXIR_API_KEY || '').trim();
  const networkName = String(
    networkData?.networkName || campaignData?.networkName || resolvedNetworkId || 'Ad Network',
  );
  const clicksSupported = Boolean(networkData?.clicksSupported ?? false);
  const analyticsNetId = resolvedNetworkId || 'default_network';

  // 0a. AppLixir status rejection check
  const appLixirStatusLower = (input.applixirParams?.status || '').trim().toLowerCase();
  if (
    appLixirStatusLower &&
    ['failed', 'fail', 'cancelled', 'canceled', 'rejected', 'error', '0', 'false'].includes(
      appLixirStatusLower,
    )
  ) {
    const failId = sanitizeId(`cb_rej_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
    await Promise.all([
      ctx.db.collection('adCallbacks').doc(failId).set({
        callbackId: failId,
        eventId: effectiveEventId,
        networkId: analyticsNetId,
        campaignId: input.campaignId || '',
        sessionId: input.sessionId,
        userId: input.userId,
        status: 'rejected',
        signatureValid: true,
        timestampValid: true,
        replayDetected: false,
        rewardPoints: 0,
        rejectionReason: 'APPLIXIR_STATUS_NOT_COMPLETED',
        callbackTimestampSec: parseCallbackTimestampSec(input.rawTimestamp) ?? 0,
        createdAt: FieldValue.serverTimestamp(),
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: 'callback_status_rejected',
        severity: 'warning',
        status: 'rejected',
        details: `Rejected non-completed AppLixir callback status="${appLixirStatusLower}" for session=${input.sessionId}`,
      }),
    ]);
    return { httpStatus: 403, body: { ok: false, error: 'APPLIXIR_STATUS_NOT_COMPLETED' } };
  }

  // 0b. Monetag official reward_event_type check (only 'valued' may credit; reject 'non_valued')
  const monetagEventLower = (input.monetagParams?.rewardEventType || '').trim().toLowerCase();
  if (
    monetagEventLower &&
    (monetagEventLower !== 'valued' ||
      ['non_valued', 'non-valued', 'not_valued', 'not-valued', 'rejected', 'failed', '0', 'false'].includes(
        monetagEventLower,
      ))
  ) {
    const failId = sanitizeId(`cb_rej_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
    await Promise.all([
      ctx.db.collection('adCallbacks').doc(failId).set({
        callbackId: failId,
        eventId: effectiveEventId,
        networkId: analyticsNetId,
        campaignId: input.campaignId || '',
        sessionId: input.sessionId,
        userId: input.userId,
        status: 'rejected',
        signatureValid: true,
        timestampValid: true,
        replayDetected: false,
        rewardPoints: 0,
        rejectionReason: 'MONETAG_EVENT_NON_VALUED',
        callbackTimestampSec: parseCallbackTimestampSec(input.rawTimestamp) ?? 0,
        createdAt: FieldValue.serverTimestamp(),
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: 'callback_monetag_non_valued',
        severity: 'warning',
        status: 'rejected',
        details: `Rejected Monetag callback reward_event_type="${monetagEventLower}" for session=${input.sessionId}`,
      }),
    ]);
    return { httpStatus: 403, body: { ok: false, error: 'MONETAG_EVENT_NON_VALUED' } };
  }

  // 1. Validate Signature / Secret
  const payloadToSign = `${input.sessionId}:${input.userId}:${input.providerTxId}`;
  const payloadWithTs =
    input.rawTimestamp !== undefined && input.rawTimestamp !== ''
      ? `${payloadToSign}:${String(input.rawTimestamp)}`
      : payloadToSign;

  let signatureValid = false;
  if (resolvedNetworkId === 'applixir') {
    const effectiveAppLixirSecret = envAppLixirSecret || expectedNetworkSecret;
    const effectiveAppLixirApiKey = envAppLixirApiKey || storedNetworkApiKey;
    const incomingApiKey = (input.applixirParams?.gameApiKey || '').trim();
    const apiKeyMatchOk =
      !effectiveAppLixirApiKey ||
      !incomingApiKey ||
      timingSafeEqualString(incomingApiKey, effectiveAppLixirApiKey);

    if (apiKeyMatchOk && effectiveAppLixirSecret) {
      const md5Valid = Boolean(
        input.applixirParams?.signature &&
          verifyAppLixirMd5Signature({
            gameApiKey: incomingApiKey,
            gameId: input.applixirParams.gameId || '',
            userId: input.applixirParams.rawUserId || input.userId || '',
            tid: input.applixirParams.tid || input.providerTxId || '',
            signature: input.applixirParams.signature,
            secret: effectiveAppLixirSecret,
          }),
      );
      const hmacOrSecretValid =
        verifyCallbackSecretOrHmac(
          input.providedSecret || input.applixirParams?.secretKeyParam || '',
          input.providedSignature,
          payloadWithTs,
          effectiveAppLixirSecret,
        ) ||
        verifyCallbackSecretOrHmac(
          input.providedSecret || input.applixirParams?.secretKeyParam || '',
          input.providedSignature,
          payloadToSign,
          effectiveAppLixirSecret,
        );
      signatureValid = md5Valid || hmacOrSecretValid;
    }
  } else {
    const sigMatchedNetwork = expectedNetworkSecret
      ? verifyCallbackSecretOrHmac(
          input.providedSecret,
          input.providedSignature,
          payloadWithTs,
          expectedNetworkSecret,
        ) ||
        verifyCallbackSecretOrHmac(
          input.providedSecret,
          input.providedSignature,
          payloadToSign,
          expectedNetworkSecret,
        )
      : false;

    const sigMatchedGlobal = envFallbackSecret
      ? verifyCallbackSecretOrHmac(
          input.providedSecret,
          input.providedSignature,
          payloadToSign,
          envFallbackSecret,
        )
      : false;

    signatureValid = sigMatchedNetwork || sigMatchedGlobal;
  }

  if (!signatureValid) {
    const missingServerSecret =
      resolvedNetworkId === 'applixir'
        ? !envAppLixirSecret && !expectedNetworkSecret
        : !expectedNetworkSecret && !envFallbackSecret;
    const failId = sanitizeId(`cb_fail_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
    await Promise.all([
      ctx.db.collection('adCallbacks').doc(failId).set({
        callbackId: failId,
        eventId: effectiveEventId,
        networkId: analyticsNetId,
        campaignId: input.campaignId || '',
        sessionId: input.sessionId,
        userId: input.userId,
        status: 'invalid_signature',
        signatureValid: false,
        timestampValid: true,
        replayDetected: false,
        rewardPoints: 0,
        rejectionReason: missingServerSecret
          ? 'POSTBACK_SECRET_NOT_CONFIGURED'
          : 'INVALID_CALLBACK_SIGNATURE',
        callbackTimestampSec: parseCallbackTimestampSec(input.rawTimestamp) ?? 0,
        createdAt: FieldValue.serverTimestamp(),
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: 'callback_invalid_signature',
        severity: 'error',
        status: 'rejected',
        details: missingServerSecret
          ? `Server postback secret missing for ${analyticsNetId} (configure MONETAG_POSTBACK_SECRET or adNetworkSecrets/${analyticsNetId}).`
          : `Invalid callback signature/secret from IP ${input.clientIp} (eventId=${effectiveEventId}, session=${input.sessionId})`,
      }),
      recordAdAnalyticsDeltaAdmin(ctx, {
        networkId: analyticsNetId,
        networkName,
        dhakaDate: dhakaToday,
        clicksSupported,
        deltaRejected: 1,
      }),
    ]);
    return {
      httpStatus: 401,
      body: {
        ok: false,
        error: missingServerSecret
          ? 'POSTBACK_SECRET_NOT_CONFIGURED'
          : 'Unauthorized postback signature',
        ...(missingServerSecret
          ? {
              configurationError:
                'Postback secret is not configured on the backend. Set MONETAG_POSTBACK_SECRET or save Callback Secret in Admin Panel → Ad Networks.',
            }
          : {}),
      },
    };
  }

  // 2. Validate Timestamp & Anti-Expiry
  const parsedTs = parseCallbackTimestampSec(input.rawTimestamp);
  const tsCheck = validateCallbackTimestamp(parsedTs);
  if (!tsCheck.valid) {
    const expId = sanitizeId(`cb_exp_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
    await Promise.all([
      ctx.db.collection('adCallbacks').doc(expId).set({
        callbackId: expId,
        eventId: effectiveEventId,
        networkId: analyticsNetId,
        campaignId: input.campaignId || '',
        sessionId: input.sessionId,
        userId: input.userId,
        status: 'expired',
        signatureValid: true,
        timestampValid: false,
        replayDetected: false,
        rewardPoints: 0,
        rejectionReason: tsCheck.reason || 'EXPIRED_CALLBACK',
        callbackTimestampSec: parsedTs ?? 0,
        createdAt: FieldValue.serverTimestamp(),
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: 'callback_expired',
        severity: 'warning',
        status: 'expired',
        details: `${tsCheck.reason} (eventId=${effectiveEventId})`,
      }),
      recordAdAnalyticsDeltaAdmin(ctx, {
        networkId: analyticsNetId,
        networkName,
        dhakaDate: dhakaToday,
        clicksSupported,
        deltaRejected: 1,
      }),
    ]);
    return { httpStatus: 409, body: { ok: false, error: 'EXPIRED_CALLBACK' } };
  }

  // 3. Required parameter check
  if (!input.sessionId || !input.userId || !input.adId || !input.providerTxId) {
    return { httpStatus: 400, body: { ok: false, error: 'Missing required postback parameters' } };
  }

  // Resolve early-callback duration holding
  let heldSessionReleaseSec = 0;
  let shouldHoldEarlyCallback = false;
  const sessSnap = await ctx.db.collection('adSessions').doc(input.sessionId).get();
  if (sessSnap.exists) {
    const sessData = sessSnap.data()!;
    const sessCreatedAtMs = toMillis(sessData.createdAt);
    if (
      sessData.status === 'pending' &&
      sessData.userId === input.userId &&
      sessData.adId === input.adId &&
      sessCreatedAtMs > 0
    ) {
      let requiredDurationSec = MIN_AD_VIEW_DURATION_SEC;
      if (input.adId === DAILY_CHECKIN_BONUS_AD_ID) {
        const bonusSnap = await ctx.db.collection('appSettings').doc('dailyBonus').get();
        if (bonusSnap.exists) {
          requiredDurationSec = normalizeAdDurationSeconds(bonusSnap.data()!.durationSeconds);
        }
      } else {
        const adSnap = await ctx.db.collection('advertisements').doc(input.adId).get();
        if (adSnap.exists) {
          requiredDurationSec = normalizeAdDurationSeconds(adSnap.data()!.estimatedDuration);
        }
      }
      const elapsedSinceStartSec = (Date.now() - sessCreatedAtMs) / 1000;
      if (elapsedSinceStartSec < requiredDurationSec) {
        shouldHoldEarlyCallback = true;
        heldSessionReleaseSec = Math.max(1, Math.ceil(requiredDurationSec - elapsedSinceStartSec));
      }
    }
  }

  // 4. Replay Attack / Duplicate Event ID protection
  const existingCb = await callbackRef.get();
  if (existingCb.exists) {
    const existingStatus = String(existingCb.data()?.status || '');
    if (existingStatus === 'awaiting_duration') {
      if (shouldHoldEarlyCallback) {
        return {
          httpStatus: 202,
          body: {
            ok: true,
            status: 'awaiting_duration',
            callbackId,
            eventId: effectiveEventId,
            sessionId: input.sessionId,
            releaseAfterSec: heldSessionReleaseSec,
          },
        };
      }
    } else {
      const dupId = sanitizeId(`cb_dup_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
      await Promise.all([
        ctx.db.collection('adCallbacks').doc(dupId).set({
          callbackId: dupId,
          eventId: effectiveEventId,
          networkId: analyticsNetId,
          campaignId: input.campaignId || '',
          sessionId: input.sessionId,
          userId: input.userId,
          status: 'duplicate',
          signatureValid: true,
          timestampValid: true,
          replayDetected: true,
          rewardPoints: 0,
          rejectionReason: 'DUPLICATE_CALLBACK_EVENT',
          callbackTimestampSec: parsedTs ?? 0,
          createdAt: FieldValue.serverTimestamp(),
        }),
        writeAdNetworkLogAdmin(ctx, {
          networkId: analyticsNetId,
          eventType: 'callback_replay_blocked',
          severity: 'error',
          status: 'duplicate',
          details: `Blocked duplicate callback eventId=${effectiveEventId} (providerTxId=${input.providerTxId})`,
        }),
        recordAdAnalyticsDeltaAdmin(ctx, {
          networkId: analyticsNetId,
          networkName,
          dhakaDate: dhakaToday,
          clicksSupported,
          deltaRejected: 1,
        }),
      ]);
      return { httpStatus: 409, body: { ok: false, error: 'DUPLICATE_CALLBACK_EVENT' } };
    }
  }

  // 5. Network & Campaign Eligibility
  if (networkData) {
    if (!networkData.enabled) {
      return { httpStatus: 403, body: { ok: false, error: 'NETWORK_DISABLED' } };
    }
    if (
      !networkData.rewardEnabled ||
      !networkData.incentivizedTrafficAllowed ||
      !networkData.rewardVerificationSupported
    ) {
      return { httpStatus: 403, body: { ok: false, error: 'NETWORK_REWARD_NOT_ELIGIBLE' } };
    }
  }

  if (campaignData) {
    if (campaignData.status !== 'active') {
      return { httpStatus: 403, body: { ok: false, error: 'CAMPAIGN_DISABLED' } };
    }
    if (
      !campaignData.rewardEligible ||
      !campaignData.incentivizedTrafficAllowed ||
      campaignData.rewardVerificationMethod === 'none'
    ) {
      return { httpStatus: 403, body: { ok: false, error: 'CAMPAIGN_REWARD_INELIGIBLE' } };
    }
    const campDate = String(campaignData.globalCompletedDhakaDate || '');
    const campCount = campDate === dhakaToday ? Number(campaignData.globalCompletedToday || 0) : 0;
    const globalDailyLimit = Math.max(1, Number(campaignData.globalDailyLimit || 1));
    if (campCount >= globalDailyLimit) {
      return { httpStatus: 429, body: { ok: false, error: 'CAMPAIGN_GLOBAL_DAILY_LIMIT_REACHED' } };
    }
  }

  // 5b. Hold early (<30s) S2S callbacks cleanly until 30s completes
  if (shouldHoldEarlyCallback) {
    await Promise.all([
      callbackRef.set(
        {
          callbackId,
          eventId: effectiveEventId,
          networkId: analyticsNetId,
          campaignId: input.campaignId || '',
          sessionId: input.sessionId,
          userId: input.userId,
          adId: input.adId,
          providerTxId: input.providerTxId,
          status: 'awaiting_duration',
          signatureValid: true,
          timestampValid: true,
          replayDetected: false,
          rewardPoints: 0,
          rejectionReason: '',
          callbackTimestampSec: parsedTs ?? Math.floor(Date.now() / 1000),
          createdAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      ),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: 'callback_awaiting_duration',
        severity: 'info',
        status: 'awaiting_duration',
        details: `Verified S2S callback held until 30s timer completes (session=${input.sessionId}, releaseAfter=${heldSessionReleaseSec}s)`,
      }),
    ]);
    return {
      httpStatus: 202,
      body: {
        ok: true,
        status: 'awaiting_duration',
        callbackId,
        eventId: effectiveEventId,
        sessionId: input.sessionId,
        releaseAfterSec: heldSessionReleaseSec,
      },
    };
  }

  // 6. Execute Atomic Reward Transaction
  try {
    const outcome = await executeVerifiedAdRewardTransactionAdmin(ctx, {
      sessionId: input.sessionId,
      userId: input.userId,
      adId: input.adId,
      providerTxId: input.providerTxId,
      verificationSource: 'S2S Postback',
    });

    await Promise.all([
      callbackRef.set(
        {
          callbackId,
          eventId: effectiveEventId,
          networkId: analyticsNetId,
          campaignId: input.campaignId || '',
          sessionId: input.sessionId,
          userId: input.userId,
          adId: input.adId,
          providerTxId: input.providerTxId,
          status: 'processed',
          signatureValid: true,
          timestampValid: true,
          replayDetected: false,
          rewardPoints: outcome.rewardPoints,
          rejectionReason: '',
          callbackTimestampSec: parsedTs ?? Math.floor(Date.now() / 1000),
          createdAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      ),
      recordAdAnalyticsDeltaAdmin(ctx, {
        networkId: analyticsNetId,
        networkName,
        dhakaDate: dhakaToday,
        clicksSupported,
        deltaImpressions: 1,
        deltaVerified: 1,
        deltaRewards: outcome.rewardPoints,
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: 'callback_processed',
        severity: 'info',
        status: 'processed',
        details: `Verified S2S completion for user=${input.userId}, ad=${input.adId}, eventId=${effectiveEventId}, +${outcome.rewardPoints} Pts`,
      }),
      resolvedNetworkId
        ? ctx.db
            .collection('adNetworks')
            .doc(resolvedNetworkId)
            .update({
              healthStatus: 'connected',
              healthMessage: `Live S2S callback verified (${dhakaToday}).`,
              updatedAt: FieldValue.serverTimestamp(),
            })
            .catch(() => {})
        : Promise.resolve(),
      processReferralQualificationAdmin(ctx, input.userId),
      writeSecurityAuditLogAdmin(ctx, {
        userId: input.userId,
        eventType: 'ad_reward_credited',
        category: 'ad_reward',
        severity: 'info',
        transactionId: outcome.txId,
        details: `Verified S2S callback credited +${outcome.rewardPoints} Pts for ad ${input.adId} (session ${input.sessionId})`,
      }),
    ]);

    return {
      httpStatus: 200,
      body: { ok: true, callbackId, eventId: effectiveEventId, ...outcome },
    };
  } catch (err) {
    const code = err instanceof Error ? err.message : 'UNKNOWN_ERROR';
    const rejId = sanitizeId(`cb_rej_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`);
    const isDuplicate = code === 'DUPLICATE_PROVIDER_TX';

    await Promise.all([
      ctx.db.collection('adCallbacks').doc(rejId).set({
        callbackId: rejId,
        eventId: effectiveEventId,
        networkId: analyticsNetId,
        campaignId: input.campaignId || '',
        sessionId: input.sessionId,
        userId: input.userId,
        status: isDuplicate ? 'duplicate' : 'rejected',
        signatureValid: true,
        timestampValid: true,
        replayDetected: isDuplicate,
        rewardPoints: 0,
        rejectionReason: code.slice(0, 280),
        callbackTimestampSec: parsedTs ?? 0,
        createdAt: FieldValue.serverTimestamp(),
      }),
      recordAdAnalyticsDeltaAdmin(ctx, {
        networkId: analyticsNetId,
        networkName,
        dhakaDate: dhakaToday,
        clicksSupported,
        deltaRejected: 1,
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId: analyticsNetId,
        eventType: isDuplicate ? 'callback_duplicate_tx' : 'callback_rejected',
        severity: isDuplicate ? 'error' : 'warning',
        status: isDuplicate ? 'duplicate' : 'rejected',
        details: `Callback rejected (${code}): sessionId=${input.sessionId}, providerTxId=${input.providerTxId}`,
      }),
    ]);

    return { httpStatus: 409, body: { ok: false, error: code } };
  }
}

export function generateSessionId(prefix: string, uid: string): string {
  return sanitizeId(`${prefix}_${Date.now()}_${uid.slice(0, 6)}_${crypto.randomBytes(6).toString('hex')}`);
}
