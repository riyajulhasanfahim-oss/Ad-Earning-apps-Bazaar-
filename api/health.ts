import type { ServerResponse } from 'node:http';
import { FieldValue } from 'firebase-admin/firestore';
import {
  type ApiRequest,
  applyCors,
  getFirebaseAdminDiagnostics,
  getQueryParams,
  isCredentialOrPermissionError,
  resolveTargetFirebase,
  sendJson,
} from './_firebaseAdmin.ts';

type HealthCheckStatus = 'SUCCESS' | 'FAILED';

interface HealthCheckItem {
  status: HealthCheckStatus;
  label: string;
  detail: string;
}

export default async function handler(req: ApiRequest, res: ServerResponse): Promise<void> {
  if (req.method === 'OPTIONS') {
    applyCors(req, res);
    res.statusCode = 204;
    res.end();
    return;
  }

  const query = getQueryParams(req);
  const isLightProbe = String(query.probe || '').toLowerCase() === 'light';
  const { projectId, databaseId } = resolveTargetFirebase(req);
  const { ctx, diagnostics } = getFirebaseAdminDiagnostics(projectId, databaseId);

  const adminOk =
    diagnostics.adminInitialized &&
    Boolean(ctx) &&
    diagnostics.projectIdMatched &&
    diagnostics.databaseIdConfigured;

  let adminDetail = '';
  if (adminOk && ctx) {
    adminDetail = ctx.hasExplicitCert
      ? `Initialized with explicit Service Account (${diagnostics.credentialInspection.clientEmailMasked || 'configured'}) for project "${ctx.projectId}" (DB "${ctx.databaseId}").`
      : `Initialized via runtime Application Default Credentials for project "${ctx.projectId}" (DB "${ctx.databaseId}").`;
  } else {
    adminDetail =
      diagnostics.configurationError ||
      diagnostics.initError ||
      'Firebase Admin SDK failed to initialize.';
  }

  const firebaseAdminInitialized: HealthCheckItem = {
    status: adminOk ? 'SUCCESS' : 'FAILED',
    label: 'Firebase Admin Initialized',
    detail: adminDetail,
  };

  let readOk = false;
  let readDetail = 'Skipped because Firebase Admin SDK is not initialized.';
  let writeOk = false;
  let writeDetail = isLightProbe
    ? 'Write probe skipped in light preflight mode.'
    : 'Skipped because Firestore connection failed.';

  let dbMonetagSecretPresent = false;
  let monetagEnabled = true;

  if (ctx) {
    try {
      await ctx.db.collection('appSettings').doc('wallet').get();
      readOk = true;
      readDetail = `Connected and read verified on project "${ctx.projectId}", database "${ctx.databaseId}".`;
    } catch (err) {
      readOk = false;
      const errMsg = err instanceof Error ? err.message : 'FIRESTORE_READ_FAILED';
      readDetail = isCredentialOrPermissionError(err)
        ? `Firestore Read Permission Denied (${errMsg}). Verify Service Account IAM role (roles/datastore.user) and Project/Database match.`
        : `Firestore Read Error: ${errMsg}`;
    }

    if (readOk && !isLightProbe) {
      try {
        const probeRef = ctx.db.collection('rateLimits').doc('_health_write_probe');
        await probeRef.set({
          actionName: 'health_probe',
          actorId: 'system_health',
          environment: diagnostics.environment,
          count: 1,
          windowStartMs: Date.now(),
          updatedAt: FieldValue.serverTimestamp(),
        });
        await probeRef.delete();
        writeOk = true;
        writeDetail = `Verified live Firestore write & cleanup on database "${ctx.databaseId}".`;
      } catch (err) {
        writeOk = false;
        const errMsg = err instanceof Error ? err.message : 'FIRESTORE_WRITE_FAILED';
        writeDetail = isCredentialOrPermissionError(err)
          ? `Firestore Write Permission Denied (${errMsg}). Grant roles/datastore.user (Cloud Datastore User) to the Service Account.`
          : `Firestore Write Error: ${errMsg}`;
      }
    } else if (!isLightProbe) {
      writeOk = false;
      writeDetail = `Cannot verify write permission until Firestore connection succeeds (${readDetail}).`;
    }

    if (readOk) {
      try {
        const [netSnap, secSnap] = await Promise.all([
          ctx.db.collection('adNetworks').doc('monetag').get(),
          ctx.db.collection('adNetworkSecrets').doc('monetag').get(),
        ]);
        if (netSnap.exists) {
          const nd = netSnap.data()!;
          monetagEnabled = Boolean(nd.enabled) && Boolean(nd.rewardEnabled);
        }
        if (secSnap.exists && typeof secSnap.data()?.callbackSecret === 'string') {
          dbMonetagSecretPresent = Boolean(String(secSnap.data()?.callbackSecret).trim());
        }
      } catch {
        // Non-blocking lookup
      }
    }
  }

  const firestoreConnected: HealthCheckItem = {
    status: readOk ? 'SUCCESS' : 'FAILED',
    label: 'Firestore Connected',
    detail: readDetail,
  };

  const firestoreWritePermission: HealthCheckItem = {
    status: writeOk ? 'SUCCESS' : 'FAILED',
    label: 'Firestore Write Permission',
    detail: writeDetail,
  };

  const envMonetagSecretPresent = Boolean(
    (process.env.MONETAG_POSTBACK_SECRET || process.env.POSTBACK_SECRET || '').trim(),
  );
  const hasAnyPostbackSecret = envMonetagSecretPresent || dbMonetagSecretPresent;
  const monetagReady =
    adminOk &&
    readOk &&
    (isLightProbe ? readOk : writeOk) &&
    hasAnyPostbackSecret &&
    monetagEnabled;

  let monetagDetail = '';
  if (!adminOk || !readOk || (!isLightProbe && !writeOk)) {
    monetagDetail =
      'Blocked because backend Firestore read/write access is required to record Monetag S2S callbacks and credit wallets.';
  } else if (!hasAnyPostbackSecret) {
    monetagDetail =
      'Monetag S2S Postback secret is missing. Set MONETAG_POSTBACK_SECRET in Vercel Environment Variables or save a Callback Secret in Admin Panel → Ad Networks → Monetag.';
  } else if (!monetagEnabled) {
    monetagDetail =
      'Monetag network is currently disabled or rewards are turned off in Admin Panel → Ad Networks.';
  } else {
    monetagDetail = envMonetagSecretPresent
      ? 'Monetag S2S postback secret (env) and /api/verifyAdNetworkCallback?net=monetag (ymid + reward_event_type=valued) ready.'
      : 'Monetag S2S postback secret (adNetworkSecrets/monetag) and /api/verifyAdNetworkCallback?net=monetag ready.';
  }

  const monetagPostbackConfigured: HealthCheckItem = {
    status: monetagReady ? 'SUCCESS' : 'FAILED',
    label: 'Monetag Postback Configured',
    detail: monetagDetail,
  };

  const rewardApiReady = adminOk && readOk && (isLightProbe ? readOk : writeOk);
  const rewardVerificationApiWorking: HealthCheckItem = {
    status: rewardApiReady ? 'SUCCESS' : 'FAILED',
    label: 'Reward Verification API Working',
    detail: rewardApiReady
      ? '/api/createAdSession, /api/verifyAdNetworkCallback, and /api/verifyAdSessionReward have verified Firestore Admin read/write access.'
      : 'Reward verification APIs cannot verify sessions or credit wallets until Firebase Admin & Firestore read/write access pass.',
  };

  const firestoreAccessVerified = isLightProbe ? readOk : readOk && writeOk;
  const allHealthy =
    firebaseAdminInitialized.status === 'SUCCESS' &&
    firestoreConnected.status === 'SUCCESS' &&
    (isLightProbe || firestoreWritePermission.status === 'SUCCESS') &&
    monetagPostbackConfigured.status === 'SUCCESS' &&
    rewardVerificationApiWorking.status === 'SUCCESS';

  let configurationError = diagnostics.configurationError;
  if (!configurationError && adminOk && (!readOk || (!isLightProbe && !writeOk))) {
    if (diagnostics.environment === 'ai_studio_preview' && !ctx?.hasExplicitCert) {
      configurationError =
        'AI Studio Preview container lacks explicit FIREBASE_SERVICE_ACCOUNT_JSON and default runtime identity lacks Firestore IAM access (7 PERMISSION_DENIED). In Vercel Production, configure FIREBASE_SERVICE_ACCOUNT_JSON + FIREBASE_PROJECT_ID + FIRESTORE_DATABASE_ID.';
    } else {
      configurationError = writeOk ? readDetail : writeDetail;
    }
  } else if (!configurationError && !monetagReady && rewardApiReady) {
    configurationError = monetagDetail;
  }

  const reason = firestoreAccessVerified
    ? 'OK'
    : diagnostics.credentialInspection.status === 'malformed'
      ? 'FIREBASE_SERVICE_ACCOUNT_JSON_MALFORMED'
      : diagnostics.credentialInspection.status === 'project_mismatch'
        ? 'SERVICE_ACCOUNT_PROJECT_MISMATCH'
        : !ctx
          ? 'FIREBASE_SERVICE_ACCOUNT_JSON_MISSING'
          : 'SERVER_CREDENTIALS_MISSING_OR_PERMISSION_DENIED';

  sendJson(req, res, 200, {
    ok: true,
    allHealthy,
    service: 'adview-reward-backend',
    environment: diagnostics.environment,
    environmentLabel: diagnostics.environmentLabel,
    targetProjectId: diagnostics.targetProjectId,
    targetDatabaseId: diagnostics.targetDatabaseId,
    bundledProjectId: diagnostics.bundledProjectId,
    bundledDatabaseId: diagnostics.bundledDatabaseId,
    projectIdMatched: diagnostics.projectIdMatched,
    databaseIdConfigured: diagnostics.databaseIdConfigured,
    serviceAccountProjectId: diagnostics.credentialInspection.serviceAccountProjectId || null,
    clientEmailMasked: diagnostics.credentialInspection.clientEmailMasked || null,
    credentialStatus: diagnostics.credentialInspection.status,
    credentialSource: diagnostics.credentialInspection.source,
    firebaseProjectConfigured: Boolean(projectId),
    serverCredentialsConfigured: firestoreAccessVerified,
    firestoreAccessVerified,
    explicitServiceAccountConfigured: Boolean(ctx?.hasExplicitCert),
    configurationError: configurationError || null,
    reason,
    checks: {
      firebaseAdminInitialized,
      firestoreConnected,
      firestoreWritePermission,
      monetagPostbackConfigured,
      rewardVerificationApiWorking,
    },
    timestamp: new Date().toISOString(),
  });
}
