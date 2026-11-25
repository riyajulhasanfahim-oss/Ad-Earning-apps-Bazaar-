import 'dotenv/config';
import express, { type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import type { ServerResponse } from 'node:http';
import type { ApiRequest } from './api/_firebaseAdmin.ts';
import cancelAdSessionHandler from './api/cancelAdSession.ts';
import confirmSdkAdCompletionHandler from './api/confirmSdkAdCompletion.ts';
import createAdSessionHandler from './api/createAdSession.ts';
import healthHandler from './api/health.ts';
import saveAdNetworkConfigHandler from './api/saveAdNetworkConfig.ts';
import startDailyBonusSessionHandler from './api/startDailyBonusSession.ts';
import testAdNetworkConnectionHandler from './api/testAdNetworkConnection.ts';
import updateDailyBonusAdSettingsHandler from './api/updateDailyBonusAdSettings.ts';
import verifyAdNetworkCallbackHandler from './api/verifyAdNetworkCallback.ts';
import verifyAdRewardPostbackHandler from './api/verifyAdRewardPostback.ts';
import verifyAdSessionRewardHandler from './api/verifyAdSessionReward.ts';

type ApiHandler = (req: ApiRequest, res: ServerResponse) => Promise<void> | void;

function wrapApiHandler(handler: ApiHandler) {
  return async (req: Request, res: Response) => {
    try {
      const apiReq = req as unknown as ApiRequest;
      await handler(apiReq, res);
    } catch (err) {
      if (!res.headersSent) {
        res.status(500).json({
          ok: false,
          error: err instanceof Error ? err.message : 'INTERNAL_SERVER_ERROR',
        });
      }
    }
  };
}

async function startServer(): Promise<void> {
  const app = express();
  const port = Number(process.env.PORT || 3000);
  const rootDir = import.meta.dirname ?? process.cwd();

  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true }));

  const apiRoutes: Record<string, ApiHandler> = {
    '/api/health': healthHandler,
    '/api/createAdSession': createAdSessionHandler,
    '/api/startDailyBonusSession': startDailyBonusSessionHandler,
    '/api/verifyAdSessionReward': verifyAdSessionRewardHandler,
    '/api/cancelAdSession': cancelAdSessionHandler,
    '/api/verifyAdNetworkCallback': verifyAdNetworkCallbackHandler,
    '/api/verifyAdRewardPostback': verifyAdRewardPostbackHandler,
    '/api/confirmSdkAdCompletion': confirmSdkAdCompletionHandler,
    '/api/saveAdNetworkConfig': saveAdNetworkConfigHandler,
    '/api/testAdNetworkConnection': testAdNetworkConnectionHandler,
    '/api/updateDailyBonusAdSettings': updateDailyBonusAdSettingsHandler,
  };

  for (const [routePath, handler] of Object.entries(apiRoutes)) {
    app.all(routePath, wrapApiHandler(handler));
  }

  app.use('/api', (_req, res) => {
    res.status(404).json({ ok: false, error: 'API_ROUTE_NOT_FOUND' });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(rootDir, 'dist');
    const indexPath = path.join(distDir, 'index.html');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(404).send('Build output not found.');
      }
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`AdView Earn server listening on http://0.0.0.0:${port}`);
  });
}

void startServer();
