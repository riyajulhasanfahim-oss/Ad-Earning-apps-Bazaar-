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
  if (!networkId) {
    sendJson(req, res, 400, { ok: false, error: 'networkId is required' });
    return;
  }

  try {
    const [netSnap, secSnap, cbSnap] = await Promise.all([
      ctx.db.collection('adNetworks').doc(networkId).get(),
      ctx.db.collection('adNetworkSecrets').doc(networkId).get(),
      ctx.db
        .collection('adCallbacks')
        .where('networkId', '==', networkId)
        .where('status', '==', 'processed')
        .limit(1)
        .get(),
    ]);

    if (!netSnap.exists) {
      sendJson(req, res, 404, { ok: false, error: 'AD_NETWORK_NOT_FOUND' });
      return;
    }

    const net = netSnap.data()!;
    const sec = secSnap.exists ? secSnap.data()! : {};
    const appLixirEnv = networkId === 'applixir' ? getAppLixirBackendEnvStatus() : null;
    const secretConfigured =
      networkId === 'applixir'
        ? Boolean(
            (sec.callbackSecret || appLixirEnv?.secretKeyConfigured) &&
              (sec.apiKey || appLixirEnv?.apiKeyConfigured),
          )
        : Boolean(sec.callbackSecret || sec.apiKey || net.secretConfigured);
    const hasVerifiedCallbacks = !cbSnap.empty;

    let apiCheckOk: boolean | null = null;
    let apiCheckError = '';

    const apiBaseUrl = String(net.apiBaseUrl || '').trim();
    const apiKey = String(
      sec.apiKey || (networkId === 'applixir' ? process.env.APPLIXIR_API_KEY || '' : ''),
    ).trim();
    if (apiBaseUrl && /^https:\/\/[a-zA-Z0-9.-]+/.test(apiBaseUrl) && apiKey) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const resp = await fetch(apiBaseUrl, {
          method: 'HEAD',
          headers: { Authorization: `Bearer ${apiKey}` },
          signal: controller.signal,
        });
        clearTimeout(timeout);
        if (resp.ok || resp.status === 405) {
          apiCheckOk = true;
        } else {
          apiCheckOk = false;
          apiCheckError = `Provider endpoint returned HTTP ${resp.status}`;
        }
      } catch (fetchErr) {
        apiCheckOk = false;
        apiCheckError =
          fetchErr instanceof Error ? fetchErr.message : 'Provider API endpoint unreachable';
      }
    }

    const effectiveWebsiteId =
      String(net.websiteId || '') ||
      (networkId === 'applixir' ? (process.env.APPLIXIR_SITE_ID || '').trim() : '');

    let status: 'connected' | 'configuration_required' | 'verification_pending' | 'error' | 'disabled' =
      'verification_pending';
    let message = 'Credentials stored securely on server. Awaiting first verified callback.';

    if (!net.enabled) {
      status = 'disabled';
      message = 'Network disabled by Administrator.';
    } else if (apiCheckOk === false) {
      status = 'error';
      message = apiCheckError || 'Provider API endpoint health check failed.';
    } else if (!String(net.publisherId || '').trim() && !effectiveWebsiteId.trim() && !String(net.placementId || '').trim()) {
      status = 'configuration_required';
      message = 'Missing Publisher ID, Website ID, or Placement ID.';
    } else if (net.rewardVerificationSupported && !secretConfigured) {
      status = 'configuration_required';
      message = 'Server Callback Secret or API Key is required before live S2S verification.';
    } else if (hasVerifiedCallbacks || apiCheckOk === true) {
      status = 'connected';
      message = apiCheckOk
        ? 'Connected: Provider API endpoint responded successfully.'
        : 'Connected: Verified S2S postback callbacks received.';
    }

    const testedAt = new Date().toISOString();
    await Promise.all([
      ctx.db.collection('adNetworks').doc(networkId).update({
        healthStatus: status,
        healthMessage: message.slice(0, 300),
        secretConfigured,
        lastTestedAt: testedAt,
        updatedAt: FieldValue.serverTimestamp(),
      }),
      writeAdNetworkLogAdmin(ctx, {
        networkId,
        actorUid: authCheck.auth.uid,
        actorEmail: authCheck.auth.email,
        eventType: 'network_health_checked',
        severity: status === 'error' ? 'error' : status === 'connected' ? 'info' : 'warning',
        status,
        details: message,
      }),
    ]);

    sendJson(req, res, 200, {
      ok: true,
      networkId,
      healthStatus: status,
      healthMessage: message,
      testedAt,
      ...(appLixirEnv ? { envCredentials: appLixirEnv } : {}),
    });
  } catch (err) {
    if (isCredentialOrPermissionError(err)) {
      sendBackendUnavailable(req, res);
      return;
    }
    sendJson(req, res, 500, {
      ok: false,
      error: err instanceof Error ? err.message : 'CONNECTION_TEST_FAILED',
    });
  }
}
