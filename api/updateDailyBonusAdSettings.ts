import type { ServerResponse } from 'node:http';
import { FieldValue } from 'firebase-admin/firestore';
import {
  type ApiRequest,
  applyCors,
  getFirebaseAdminContext,
  isCredentialOrPermissionError,
  normalizeAdDurationSeconds,
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

  const authCheck = await verifyAuthAndRoleAdmin(req, ctx, {
    requireVerifiedEmail: true,
    requiredAdminRole: 'admin',
  });
  if (!authCheck.auth) {
    sendJson(req, res, authCheck.status || 403, {
      ok: false,
      error: authCheck.error || 'Forbidden',
    });
    return;
  }

  const body = await readJsonBody(req);
  const enabled = body.enabled === true;
  const incentivizedTrafficAllowed = body.incentivizedTrafficAllowed === true;
  const monetagDirectLinkUrl = String(body.monetagDirectLinkUrl || '').trim().slice(0, 500);
  const rawReward = Number(body.rewardPoints ?? 0);
  const rewardPoints =
    Number.isFinite(rawReward) && rawReward >= 1 ? Math.floor(rawReward) : 0;
  const durationSeconds = normalizeAdDurationSeconds(body.durationSeconds);

  if (monetagDirectLinkUrl && !/^https:\/\/.+/i.test(monetagDirectLinkUrl)) {
    sendJson(req, res, 400, {
      ok: false,
      error: 'Monetag Direct Link URL must start with https://',
    });
    return;
  }

  if (enabled) {
    if (!/^https:\/\/.+/i.test(monetagDirectLinkUrl)) {
      sendJson(req, res, 400, {
        ok: false,
        error: 'Enter a valid HTTPS Monetag Direct Link URL before enabling.',
      });
      return;
    }
    if (rewardPoints < 1) {
      sendJson(req, res, 400, {
        ok: false,
        error: 'Daily Bonus Reward Points must be at least 1.',
      });
      return;
    }
    if (!incentivizedTrafficAllowed) {
      sendJson(req, res, 400, {
        ok: false,
        error: 'Monetag Incentivized Traffic approval confirmation is required when enabled.',
      });
      return;
    }
  }

  const nowServer = FieldValue.serverTimestamp();
  const dailyBonusRef = ctx.db.collection('appSettings').doc('dailyBonus');

  try {
    const prevSnap = await dailyBonusRef.get();
    const prev = prevSnap.exists ? prevSnap.data()! : {};

    const payload = {
      enabled,
      monetagDirectLinkUrl,
      rewardPoints,
      durationSeconds,
      incentivizedTrafficAllowed,
      updatedAt: nowServer,
    };

    const admLogId = sanitizeId(`adm_${Date.now()}_dailyBonus`);
    const ops: Array<Promise<unknown>> = [
      dailyBonusRef.set(payload, { merge: true }),
      ctx.db
        .collection('adminLogs')
        .doc(admLogId)
        .set({
          logId: admLogId,
          adminUid: authCheck.auth.uid,
          adminEmail: authCheck.auth.email || 'admin@adviewearn.com',
          action: 'daily_bonus_settings_updated',
          targetId: 'dailyBonus',
          previousValue: `enabled=${Boolean(prev.enabled)}, pts=${Number(prev.rewardPoints || 0)}, sec=${Number(prev.durationSeconds || 30)}`,
          newValue: `enabled=${enabled}, pts=${rewardPoints}, sec=${durationSeconds}`,
          details: `Updated Daily Check-in Bonus Monetag Direct Link config (enabled=${enabled}, reward=${rewardPoints} Pts, duration=${durationSeconds}s)`,
          createdAt: nowServer,
        })
        .catch(() => {}),
    ];

    if (rewardPoints >= 1) {
      ops.push(
        ctx.db
          .collection('appSettings')
          .doc('wallet')
          .set({ dailyBonusPoints: rewardPoints, updatedAt: nowServer }, { merge: true }),
        ctx.db
          .collection('appConfig')
          .doc('economy')
          .set({ dailyBonusPoints: rewardPoints, updatedAt: nowServer }, { merge: true }),
      );
    }

    await Promise.all(ops);
    sendJson(req, res, 200, {
      ok: true,
      config: {
        enabled,
        monetagDirectLinkUrl,
        rewardPoints,
        durationSeconds,
        incentivizedTrafficAllowed,
      },
    });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(req, res);
      return;
    }
    sendJson(req, res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'DAILY_BONUS_SETTINGS_UPDATE_FAILED',
    });
  }
}
