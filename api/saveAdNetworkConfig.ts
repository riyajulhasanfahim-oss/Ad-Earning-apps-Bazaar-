import type { ServerResponse } from 'node:http';
import { FieldValue } from 'firebase-admin/firestore';
import {
  type ApiRequest,
  applyCors,
  getAppLixirBackendEnvStatus,
  getFirebaseAdminContext,
  isCredentialOrPermissionError,
  readJsonBody,
  resolveTargetFirebase,
  sanitizeId,
  sendBackendUnavailable,
  sendJson,
  verifyAuthAndRoleAdmin,
} from './_firebaseAdmin.ts';
import { writeAdNetworkLogAdmin } from './_rewardEngine.ts';

function resolveNetworkHealthStatus(input: {
  enabled: boolean;
  publisherId: string;
  websiteId: string;
  placementId: string;
  integrationType: string;
  rewardVerificationSupported: boolean;
  secretConfigured: boolean;
}): {
  status: 'connected' | 'configuration_required' | 'verification_pending' | 'error' | 'disabled';
  message: string;
} {
  if (!input.enabled) {
    return { status: 'disabled', message: 'Network disabled by Administrator.' };
  }
  const hasAnyId = Boolean(
    input.publisherId.trim() || input.websiteId.trim() || input.placementId.trim(),
  );
  if (!hasAnyId) {
    return {
      status: 'configuration_required',
      message: 'Missing Publisher ID, Website ID, or Placement ID.',
    };
  }
  const needsSecret =
    input.integrationType === 's2s_postback' ||
    input.integrationType === 'sdk_callback' ||
    input.integrationType === 'hybrid';
  if (needsSecret && input.rewardVerificationSupported && !input.secretConfigured) {
    return {
      status: 'configuration_required',
      message: 'Server Callback Secret or API Key is required before live S2S verification.',
    };
  }
  return {
    status: 'verification_pending',
    message: 'Credentials stored securely on server. Awaiting first verified callback.',
  };
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
  const networkId = sanitizeId(String(body.networkId || '').trim().toLowerCase());
  const networkName = String(body.networkName || '').trim().slice(0, 80);

  if (!networkId || networkName.length < 2) {
    sendJson(req, res, 400, { ok: false, error: 'Valid networkId and networkName are required.' });
    return;
  }

  const incentivizedTrafficAllowed = Boolean(body.incentivizedTrafficAllowed);
  const rewardVerificationSupported = Boolean(body.rewardVerificationSupported);
  const requestedRewardEnabled = Boolean(body.rewardEnabled);

  if (requestedRewardEnabled && (!incentivizedTrafficAllowed || !rewardVerificationSupported)) {
    sendJson(req, res, 400, {
      ok: false,
      error:
        'REWARD_POLICY_VIOLATION: Networks lacking incentivized traffic approval or reward verification support cannot enable rewards.',
    });
    return;
  }

  const enabled = Boolean(body.enabled);
  const integrationTypeRaw = String(body.integrationType || 's2s_postback');
  const integrationType =
    integrationTypeRaw === 'sdk_callback' ||
    integrationTypeRaw === 'direct_link' ||
    integrationTypeRaw === 'hybrid'
      ? integrationTypeRaw
      : 's2s_postback';

  const logoKeyRaw = String(body.logoKey || 'custom');
  const logoKey =
    logoKeyRaw === 'monetag' || logoKeyRaw === 'applixir' || logoKeyRaw === 'adsterra'
      ? logoKeyRaw
      : 'custom';

  const publisherId = String(body.publisherId || '').trim().slice(0, 120);
  const websiteId = String(body.websiteId || '').trim().slice(0, 120);
  const placementId = String(body.placementId || '').trim().slice(0, 120);
  const directLinkUrl = String(body.directLinkUrl || '').trim().slice(0, 500);
  const apiBaseUrl = String(body.apiBaseUrl || '').trim().slice(0, 300);
  const callbackUrl = String(body.callbackUrl || '').trim().slice(0, 500);
  const postbackParamsTemplate = String(body.postbackParamsTemplate || '').trim().slice(0, 400);

  const callbackSecretInput = String(body.callbackSecret || '').trim().slice(0, 256);
  const apiKeyInput = String(body.apiKey || '').trim().slice(0, 256);
  const webhookTokenInput = String(body.webhookToken || '').trim().slice(0, 256);

  try {
    const existingSecSnap = await ctx.db.collection('adNetworkSecrets').doc(networkId).get();
    const existingSec = existingSecSnap.exists ? existingSecSnap.data()! : {};

    const nextCallbackSecret = callbackSecretInput || String(existingSec.callbackSecret || '');
    const nextApiKey = apiKeyInput || String(existingSec.apiKey || '');
    const nextWebhookToken = webhookTokenInput || String(existingSec.webhookToken || '');

    if (callbackSecretInput || apiKeyInput || webhookTokenInput) {
      await ctx.db.collection('adNetworkSecrets').doc(networkId).set(
        {
          networkId,
          callbackSecret: nextCallbackSecret,
          apiKey: nextApiKey,
          webhookToken: nextWebhookToken,
          rotatedByUid: authCheck.auth.uid,
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
    }

    const appLixirEnv = networkId === 'applixir' ? getAppLixirBackendEnvStatus() : null;
    const hasSecretKey = Boolean(nextCallbackSecret || appLixirEnv?.secretKeyConfigured);
    const hasApiKey = Boolean(nextApiKey || appLixirEnv?.apiKeyConfigured);
    const secretConfigured =
      networkId === 'applixir'
        ? Boolean(hasSecretKey && hasApiKey)
        : Boolean(nextCallbackSecret || nextApiKey);
    const secretHint = nextCallbackSecret
      ? `••••${nextCallbackSecret.slice(-4)}`
      : nextApiKey
        ? `••••${nextApiKey.slice(-4)}`
        : appLixirEnv?.secretKeyConfigured && appLixirEnv?.apiKeyConfigured
          ? 'BACKEND_ENV'
          : '';

    const effectiveWebsiteId =
      websiteId || (networkId === 'applixir' ? (process.env.APPLIXIR_SITE_ID || '').trim() : '');

    const health = resolveNetworkHealthStatus({
      enabled,
      publisherId,
      websiteId: effectiveWebsiteId,
      placementId,
      integrationType,
      rewardVerificationSupported,
      secretConfigured,
    });

    const nowServer = FieldValue.serverTimestamp();
    await ctx.db.collection('adNetworks').doc(networkId).set(
      {
        networkId,
        networkName,
        logoKey,
        integrationType,
        publisherId,
        websiteId,
        placementId,
        directLinkUrl,
        apiBaseUrl,
        callbackUrl,
        postbackParamsTemplate,
        incentivizedTrafficAllowed,
        rewardVerificationSupported,
        rewardEnabled: requestedRewardEnabled,
        clicksSupported: Boolean(body.clicksSupported),
        apiHealthSupported: Boolean(body.apiHealthSupported),
        secretConfigured,
        secretHint,
        healthStatus: health.status,
        healthMessage: health.message.slice(0, 300),
        enabled,
        lastTestedAt: new Date().toISOString(),
        updatedAt: nowServer,
      },
      { merge: true },
    );

    const admLogId = sanitizeId(`adm_${Date.now()}_${networkId}`);
    await Promise.all([
      writeAdNetworkLogAdmin(ctx, {
        networkId,
        actorUid: authCheck.auth.uid,
        actorEmail: authCheck.auth.email,
        eventType: 'network_config_saved',
        severity: 'info',
        status: health.status,
        details: `Saved config for ${networkName} (enabled=${enabled}, rewardEnabled=${requestedRewardEnabled}, secretConfigured=${secretConfigured})`,
      }),
      ctx.db
        .collection('adminLogs')
        .doc(admLogId)
        .set({
          logId: admLogId,
          adminUid: authCheck.auth.uid,
          adminEmail: authCheck.auth.email || 'admin@adviewearn.com',
          action: 'ad_network_config_updated',
          targetId: networkId,
          newValue: `enabled=${enabled}, health=${health.status}`,
          details: `Updated Ad Network ${networkName} (${networkId})`,
          createdAt: nowServer,
        })
        .catch(() => {}),
    ]);

    sendJson(req, res, 200, {
      ok: true,
      networkId,
      secretConfigured,
      healthStatus: health.status,
      healthMessage: health.message,
      ...(appLixirEnv ? { envCredentials: appLixirEnv } : {}),
    });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(req, res);
      return;
    }
    sendJson(req, res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'SAVE_AD_NETWORK_FAILED',
    });
  }
}
