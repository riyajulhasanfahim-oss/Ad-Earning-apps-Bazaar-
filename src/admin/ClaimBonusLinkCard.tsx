import React, { useEffect, useState } from 'react';
import { CheckCircle2, Gift, Loader2, Save } from 'lucide-react';
import { AdminRole } from '../types';
import { hasAdminPermission } from '../services/adminService';
import {
  MAX_AD_VIEW_SECONDS,
  MIN_AD_VIEW_SECONDS,
  normalizeAdDurationSeconds,
  saveDailyBonusAdConfig,
  subscribeToDailyBonusAdConfig,
} from '../services/dashboardService';
import { useToast } from '../components/ui/ToastProvider';

interface ClaimBonusLinkCardProps {
  adminRole: AdminRole;
  defaultBonusPoints?: number | null;
}

export const ClaimBonusLinkCard: React.FC<ClaimBonusLinkCardProps> = ({
  adminRole,
  defaultBonusPoints,
}) => {
  const { showToast } = useToast();
  const canManage = hasAdminPermission(adminRole, 'manage_ads');

  const [url, setUrl] = useState('');
  const [rewardPoints, setRewardPoints] = useState(
    defaultBonusPoints && defaultBonusPoints > 0 ? String(defaultBonusPoints) : '50',
  );
  const [durationSeconds, setDurationSeconds] = useState(String(MIN_AD_VIEW_SECONDS));
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const unsub = subscribeToDailyBonusAdConfig((cfg) => {
      setUrl(cfg.monetagDirectLinkUrl || '');
      if (cfg.rewardPoints !== null && cfg.rewardPoints > 0) {
        setRewardPoints(String(cfg.rewardPoints));
      } else if (defaultBonusPoints && defaultBonusPoints > 0) {
        setRewardPoints(String(defaultBonusPoints));
      }
      setDurationSeconds(String(normalizeAdDurationSeconds(cfg.durationSeconds)));
      setEnabled(cfg.enabled);
    });
    return () => unsub();
  }, [defaultBonusPoints]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canManage) {
      showToast('Admin or Super Admin role required.', 'error');
      return;
    }

    const cleanUrl = url.trim();
    const pts = Math.floor(Number(rewardPoints || 0));
    const sec = normalizeAdDurationSeconds(durationSeconds);

    if (enabled && !/^https:\/\/.+/i.test(cleanUrl)) {
      showToast('Enter a valid HTTPS Monetag Direct Link URL for Claim Bonus.', 'error');
      return;
    }
    if (enabled && (!Number.isFinite(pts) || pts < 1)) {
      showToast('Enter valid Claim Bonus reward points (minimum 1).', 'error');
      return;
    }

    setSaving(true);
    try {
      await saveDailyBonusAdConfig({
        enabled,
        monetagDirectLinkUrl: cleanUrl,
        rewardPoints: pts > 0 ? pts : null,
        durationSeconds: sec,
        incentivizedTrafficAllowed: true,
      });
      showToast(
        enabled
          ? `Claim Bonus Monetag link saved & activated (+${pts} Pts, ${sec}s timer).`
          : 'Claim Bonus settings saved (Inactive).',
        'success',
      );
    } catch (err) {
      showToast(
        err instanceof Error ? err.message : 'Could not save Claim Bonus Monetag link.',
        'error',
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <form
      onSubmit={handleSave}
      className="rounded-2xl p-5 bg-gradient-to-br from-[#12193F] via-[#0D1330] to-[#0B112B] border border-amber-400/30 space-y-4 text-xs"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-amber-500/20 border border-amber-400/40 flex items-center justify-center text-amber-300 shrink-0">
            <Gift className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm sm:text-base font-extrabold font-display text-white">
              Claim Bonus (Daily Check-in) — Monetag Link &amp; Reward
            </h3>
            <p className="text-xs text-slate-400">
              Set the Monetag Direct Link for the user &ldquo;Claim Bonus&rdquo; button. Clicking
              opens this link immediately, runs the 30s timer, and adds the bonus points to Wallet.
            </p>
          </div>
        </div>

        <span
          className={`px-3 py-1 rounded-full text-[11px] font-bold shrink-0 self-start sm:self-center border inline-flex items-center gap-1.5 ${
            enabled
              ? 'bg-emerald-500/15 border-emerald-400/40 text-emerald-300'
              : 'bg-slate-500/15 border-white/15 text-slate-300'
          }`}
        >
          {enabled && <CheckCircle2 className="w-3.5 h-3.5" />}
          <span>{enabled ? 'Active' : 'Inactive'}</span>
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-12 gap-3">
        <div className="sm:col-span-6 space-y-1">
          <label className="block font-semibold text-slate-300">
            Monetag Link URL (HTTPS)
          </label>
          <input
            type="url"
            disabled={!canManage}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://uplcm.com/4/..."
            className="w-full h-10 px-3 rounded-xl bg-[#070B22] border border-white/15 text-white font-mono-num focus:outline-none focus:border-amber-400 disabled:opacity-50"
          />
        </div>

        <div className="sm:col-span-3 space-y-1">
          <label className="block font-semibold text-slate-300">Bonus Points</label>
          <input
            type="number"
            min={1}
            max={100000}
            disabled={!canManage}
            value={rewardPoints}
            onChange={(e) => setRewardPoints(e.target.value)}
            placeholder="e.g. 50"
            className="w-full h-10 px-3 rounded-xl bg-[#070B22] border border-white/15 text-amber-300 font-bold font-mono-num focus:outline-none focus:border-amber-400 disabled:opacity-50"
          />
        </div>

        <div className="sm:col-span-3 space-y-1">
          <label className="block font-semibold text-slate-300">Timer (Seconds)</label>
          <input
            type="number"
            min={MIN_AD_VIEW_SECONDS}
            max={MAX_AD_VIEW_SECONDS}
            disabled={!canManage}
            value={durationSeconds}
            onChange={(e) => setDurationSeconds(e.target.value)}
            className="w-full h-10 px-3 rounded-xl bg-[#070B22] border border-white/15 text-white font-mono-num focus:outline-none focus:border-amber-400 disabled:opacity-50"
          />
        </div>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1">
        <label className="inline-flex items-center gap-2.5 cursor-pointer text-slate-200 font-semibold">
          <input
            type="checkbox"
            disabled={!canManage}
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="w-4 h-4 rounded accent-amber-500"
          />
          <span>Enable Claim Bonus Monetag Link &amp; 30s Wallet Credit</span>
        </label>

        <button
          type="submit"
          disabled={!canManage || saving}
          className="min-h-[40px] px-5 rounded-xl bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 text-[#09102A] font-extrabold inline-flex items-center justify-center gap-2 disabled:opacity-50 transition-colors"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          <span>Save Claim Bonus Link</span>
        </button>
      </div>
    </form>
  );
};
