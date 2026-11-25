import type { ServerResponse } from 'node:http';
import {
  type ApiRequest,
  applyCors,
  getClientIp,
  getFirebaseAdminContext,
  getQueryParams,
  hashNetworkIdentifier,
  isCredentialOrPermissionError,
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendBackendUnavailable,
  sendJson,
} from './_firebaseAdmin.ts';
import {
  enforceRateLimitAdmin,
  processVerifiedNetworkCallbackAdmin,
  writeSecurityAuditLogAdmin,
} from './_rewardEngine.ts';

function stripMacro(raw: unknown): string {
  const val = String(raw ?? '').trim();
  return /^\{[^}]+\}$/.test(val) ? '' : val;
}

export default async function handler(req: ApiRequest, res: ServerResponse): Promise<void> {
  if (req.method === 'OPTIONS') {
    applyCors(req, res, { allowPublicWebhook: true });
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== 'GET' && req.method !== 'POST') {
    sendJson(
      req,
      res,
      405,
      { ok: false, error: 'Method not allowed' },
      { allowPublicWebhook: true },
    );
    return;
  }

  const { projectId, databaseId } = resolveTargetFirebase(req);
  const ctx = getFirebaseAdminContext(projectId, databaseId);
  if (!ctx) {
    sendBackendUnavailable(req, res);
    return;
  }

  const queryParams = getQueryParams(req);
  const bodyParams = req.method === 'POST' ? await readJsonBody(req) : {};
  const source: Record<string, unknown> =
    req.method === 'POST' ? { ...queryParams, ...bodyParams } : queryParams;

  let customDataSessionId = '';
  let customDataAdId = '';
  const rawCustomData = source.customData;
  if (typeof rawCustomData === 'string' && rawCustomData.trim()) {
    const trimmedCustom = rawCustomData.trim();
    if (trimmedCustom.startsWith('{') && !/^\{[^}:]+\}$/.test(trimmedCustom)) {
      try {
        const parsed = JSON.parse(trimmedCustom) as Record<string, unknown>;
        customDataSessionId = stripMacro(parsed.sessionId || parsed.session_id);
        customDataAdId = stripMacro(parsed.adId || parsed.ad_id);
      } catch {
        // Ignore malformed JSON customData
      }
    } else if (!/^\{[^}]+\}$/.test(trimmedCustom)) {
      customDataSessionId = trimmedCustom;
    }
  } else if (rawCustomData && typeof rawCustomData === 'object') {
    const obj = rawCustomData as Record<string, unknown>;
    customDataSessionId = stripMacro(obj.sessionId || obj.session_id);
    customDataAdId = stripMacro(obj.adId || obj.ad_id);
  }

  const rawSessionToken = stripMacro(
    source.ymid ||
      source.sessionId ||
      source.session_id ||
      source.request_var ||
      customDataSessionId ||
      source.custom1,
  );
  const sessionId = rawSessionToken ? sanitizeId(rawSessionToken).replace(/^id_\d+$/, '') : '';
  const rawUserId = stripMacro(
    source.userId || source.user_id || source.userid || source.var,
  );
  let userId = rawUserId;
  let adId = stripMacro(source.adId || source.ad_id || customDataAdId || source.custom2 || source.sub1);

  const gameApiKey = stripMacro(source.gameApiKey);
  const gameId = stripMacro(source.gameId);
  const tid = stripMacro(source.tid || source.trans_id);
  const appLixirStatus = stripMacro(source.status);
  const appLixirSignature = stripMacro(source.signature);
  const appLixirSecretKeyParam = stripMacro(source.secretKey);
  const rewardEventType = stripMacro(source.reward_event_type);
  const estimatedPrice = stripMacro(source.estimated_price);
  const zoneId = stripMacro(source.zone_id);

  let networkId = stripMacro(source.networkId || source.network_id || source.net);
  if (!networkId && (gameApiKey || gameId || tid || appLixirSignature)) {
    networkId = 'applixir';
  } else if (
    !networkId &&
    (stripMacro(source.ymid) || zoneId || rewardEventType || estimatedPrice)
  ) {
    networkId = 'monetag';
  }

  const campaignId = stripMacro(source.campaignId || source.campaign_id);
  let providerTxId = stripMacro(
    source.providerTxId ||
      source.provider_tx_id ||
      source.tx_id ||
      source.transaction_id ||
      source.conversion_id ||
      source.request_id ||
      tid,
  );
  const rawTimestamp = source.ts ?? source.timestamp ?? req.headers['x-postback-timestamp'];

  const headerSecret = req.headers['x-postback-secret'];
  const headerSig = req.headers['x-postback-signature'];
  const providedSecret = stripMacro(
    (Array.isArray(headerSecret) ? headerSecret[0] : headerSecret) || source.secret,
  );
  const providedSignature = stripMacro(
    (Array.isArray(headerSig) ? headerSig[0] : headerSig) || source.sig,
  );

  try {
    if (sessionId) {
      const sessSnap = await ctx.db.collection('adSessions').doc(sessionId).get();
      if (!sessSnap.exists) {
        sendJson(
          req,
          res,
          404,
          { ok: false, error: 'SESSION_NOT_FOUND' },
          { allowPublicWebhook: true },
        );
        return;
      }
      const sess = sessSnap.data()!;
      const boundUserId = typeof sess.userId === 'string' ? String(sess.userId).trim() : '';
      const boundAdId = typeof sess.adId === 'string' ? String(sess.adId).trim() : '';

      if (userId && boundUserId && userId !== boundUserId) {
        sendJson(
          req,
          res,
          403,
          { ok: false, error: 'SESSION_MISMATCH' },
          { allowPublicWebhook: true },
        );
        return;
      }
      if (adId && boundAdId && adId !== boundAdId) {
        sendJson(
          req,
          res,
          403,
          { ok: false, error: 'SESSION_MISMATCH' },
          { allowPublicWebhook: true },
        );
        return;
      }

      if (boundUserId) userId = boundUserId;
      if (boundAdId) adId = boundAdId;
      if (!networkId && typeof sess.adNetwork === 'string') {
        const netLower = String(sess.adNetwork).toLowerCase();
        if (netLower.includes('monetag')) networkId = 'monetag';
        else if (netLower.includes('applixir')) networkId = 'applixir';
        else if (netLower.includes('adsterra')) networkId = 'adsterra';
      }
    }

    if (!providerTxId && networkId.toLowerCase() === 'monetag' && sessionId) {
      providerTxId = sanitizeId(`monetag_${sessionId}`);
    }
    const eventId = stripMacro(source.eventId || source.event_id) || providerTxId || '';

    const cbRate = await enforceRateLimitAdmin(ctx, {
      bucketKey: `ad_cb_${hashNetworkIdentifier(req)}_${sanitizeId(userId || 'anon').slice(0, 24)}`,
      actionName: 'verifyAdCallback',
      actorId: userId || 'callback',
      maxRequests: 40,
      windowSeconds: 60,
    });
    if (!cbRate.allowed) {
      sendJson(
        req,
        res,
        429,
        { ok: false, error: 'RATE_LIMIT_EXCEEDED', retryAfterSec: cbRate.retryAfterSec },
        { allowPublicWebhook: true },
      );
      return;
    }

    const result = await processVerifiedNetworkCallbackAdmin(ctx, {
      sessionId,
      userId,
      adId,
      providerTxId,
      eventId,
      networkId,
      campaignId,
      providedSecret,
      providedSignature,
      rawTimestamp,
      clientIp: getClientIp(req),
      applixirParams:
        networkId === 'applixir' ||
        gameApiKey ||
        gameId ||
        tid ||
        appLixirSignature ||
        appLixirStatus
          ? {
              gameApiKey,
              gameId,
              rawUserId,
              tid,
              status: appLixirStatus,
              signature: appLixirSignature,
              secretKeyParam: appLixirSecretKeyParam,
            }
          : undefined,
      monetagParams:
        networkId.toLowerCase() === 'monetag' || rewardEventType
          ? {
              rewardEventType,
              estimatedPrice,
              zoneId,
            }
          : undefined,
    });

    if (result.httpStatus >= 400) {
      const errCode = String(result.body.error || 'CALLBACK_REJECTED');
      await writeSecurityAuditLogAdmin(ctx, {
        userId: userId || 'callback',
        eventType: 'ad_reward_rejected',
        category: 'ad_reward',
        severity: errCode === 'INVALID_CALLBACK_SIGNATURE' ? 'high' : 'medium',
        transactionId: providerTxId || eventId,
        details: `Callback rejected (${errCode}) for ad ${adId || 'unknown'} (session ${sessionId || 'unknown'})`,
      });
    }

    sendJson(req, res, result.httpStatus, result.body, { allowPublicWebhook: true });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(req, res);
      return;
    }
    sendJson(
      req,
      res,
      500,
      {
        ok: false,
        error: err instanceof Error ? err.message : 'CALLBACK_PROCESSING_FAILED',
      },
      { allowPublicWebhook: true },
    );
  }
}
