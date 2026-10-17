import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft, Check, Gauge, Layers3, Sparkles, Zap } from 'lucide-react'
import api from '../services/api'
import { userFacingApiError } from '../utils/userFacingApiError'

const CONTEXT_KEY = 'shizuha_upgrade_context'

const sourceMeta = {
  cortex: { label: 'Cortex', href: '/cortex/inference-key', accent: 'from-violet-400 to-cyan-300' },
  scs: { label: 'Shizuha Cloud', href: '/scs/', accent: 'from-amber-300 to-orange-400' },
  id: { label: 'Shizuha', href: '/id/account', accent: 'from-emerald-300 to-cyan-300' },
}

function readKnownContext() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(CONTEXT_KEY) || '{}')
    const upgrade = parsed.upgrade_required || parsed.error || parsed
    return upgrade && typeof upgrade === 'object'
      ? { ...upgrade, source: parsed.source, message: parsed.message || upgrade.message || '' }
      : {}
  } catch {
    return {}
  }
}

function formatQuantity(value) {
  if (value === null || value === undefined || value === '') return '—'
  return new Intl.NumberFormat('en-IN', { maximumFractionDigits: 1 }).format(Number(value))
}

export default function Upgrade() {
  const [known] = useState(readKnownContext)
  const querySource = new URLSearchParams(window.location.search).get('source')
  const source = sourceMeta[known.source] ? known.source : (sourceMeta[querySource] ? querySource : 'id')
  const meta = sourceMeta[source]
  const [accountData, setAccountData] = useState(null)
  const [deepening, setDeepening] = useState(true)
  const [notifyState, setNotifyState] = useState('idle')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    api.get('/auth/billing/account/')
      .then((response) => active && setAccountData(response.data))
      .catch(() => {})
      .finally(() => active && setDeepening(false))
    return () => { active = false }
  }, [])

  const freePlan = useMemo(
    () => accountData?.plans?.find((plan) => plan.code === 'free-v1'),
    [accountData],
  )
  const starter = useMemo(
    () => accountData?.plans?.find((plan) => plan.status === 'notify_only'),
    [accountData],
  )

  const notify = async () => {
    setNotifyState('sending')
    setError('')
    try {
      await api.post('/auth/billing/upgrade-interest/', {
        source,
        meter: known.meter || '',
        target_plan: 'starter-999-v1-rc1',
      })
      setNotifyState('done')
    } catch (requestError) {
      setNotifyState('idle')
      setError(userFacingApiError(requestError, 'Could not save your interest. Please try again.'))
    }
  }

  return (
    <main className="min-h-screen overflow-hidden bg-[#07100f] text-white">
      <div className="pointer-events-none fixed inset-0 opacity-70" aria-hidden="true">
        <div className="absolute -left-24 top-0 h-96 w-96 rounded-full bg-emerald-500/20 blur-3xl" />
        <div className="absolute right-0 top-16 h-[28rem] w-[28rem] rounded-full bg-cyan-500/15 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-amber-400/10 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-6xl px-5 py-8 sm:px-8 lg:py-14">
        <a href={meta.href} className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-[0.18em] text-emerald-100/70 transition hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to {meta.label}
        </a>

        <section className="mt-10 grid gap-8 lg:grid-cols-[1.15fr_0.85fr] lg:items-start">
          <div>
            <div className="flex items-center gap-3">
              <span className="inline-flex h-9 items-center rounded-full border border-amber-200/20 bg-amber-200/10 px-4 font-mono text-[11px] uppercase tracking-[0.2em] text-amber-100">
                Free allowance reached
              </span>
              <span className="h-2 w-2 animate-pulse rounded-full bg-amber-300 shadow-[0_0_18px_rgba(252,211,77,.9)]" />
            </div>
            <h1 className="mt-7 max-w-3xl text-4xl font-semibold leading-[1.02] tracking-[-0.04em] sm:text-6xl">
              Keep your work. <span className={`bg-gradient-to-r ${meta.accent} bg-clip-text text-transparent`}>Unlock more room.</span>
            </h1>
            <p className="mt-6 max-w-2xl text-base leading-7 text-emerald-50/65 sm:text-lg">
              {known.message || `${meta.label} protected your account by stopping new consumption at the free-v1 limit.`}
              {' '}Existing work stays available; only new metered usage is paused.
            </p>

            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              <Metric icon={Gauge} label="Meter" value={known.meter || 'free-v1 allowance'} />
              <Metric icon={Layers3} label="Remaining" value={formatQuantity(known.remaining ?? known.remaining_tokens)} />
              <Metric icon={Zap} label="Requested" value={formatQuantity(known.requested ?? known.requested_tokens)} />
            </div>

            <div className="mt-5 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.16em] text-emerald-100/45">
              <span className={`h-1.5 w-1.5 rounded-full ${deepening ? 'animate-pulse bg-cyan-300' : 'bg-emerald-300'}`} />
              {deepening ? 'Syncing account context' : `Account context synced${accountData?.billing_account?.grant ? ` · ${accountData.billing_account.grant.plan}` : ''}`}
            </div>
          </div>

          <aside className="rounded-[2rem] border border-white/10 bg-white/[0.065] p-2 shadow-2xl shadow-black/30 backdrop-blur-xl">
            <div className="rounded-[1.55rem] border border-emerald-200/10 bg-[#0c1715]/90 p-6 sm:p-8">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-cyan-200/65">{starter?.eyebrow || 'Coming soon'}</p>
                  <h2 className="mt-2 text-3xl font-semibold tracking-tight">{starter?.name || 'Starter'}</h2>
                </div>
                <Sparkles className="h-8 w-8 text-amber-300" />
              </div>
              <p className="mt-4 text-sm leading-6 text-emerald-50/60">
                Higher shared allowances across Cortex and Shizuha Cloud. Payments stay off during preview—this button only saves your interest.
              </p>
              <ul className="mt-7 space-y-3">
                {(starter?.features || ['Higher token, storage, and compute allowances', 'More concurrent projects and runtimes', 'No checkout during preview']).map((feature) => (
                  <li key={feature} className="flex gap-3 text-sm text-emerald-50/80">
                    <Check className="mt-0.5 h-4 w-4 flex-none text-emerald-300" /> {feature}
                  </li>
                ))}
              </ul>
              <button
                type="button"
                onClick={notify}
                disabled={notifyState !== 'idle'}
                className="mt-8 w-full rounded-xl bg-gradient-to-r from-emerald-300 to-cyan-300 px-5 py-3.5 text-sm font-semibold text-[#06100e] shadow-lg shadow-emerald-900/30 transition hover:-translate-y-0.5 hover:shadow-emerald-400/20 disabled:translate-y-0 disabled:cursor-default disabled:opacity-80"
              >
                {notifyState === 'done' ? 'You’re on the preview list' : notifyState === 'sending' ? 'Saving…' : 'Notify me when Starter opens'}
              </button>
              <p className="mt-3 text-center font-mono text-[10px] uppercase tracking-[0.16em] text-emerald-100/35">Mock provider · no payment collected</p>
              {error && <p className="mt-4 rounded-lg border border-amber-300/15 bg-amber-300/10 px-3 py-2 text-sm text-amber-100">{error}</p>}
            </div>
          </aside>
        </section>

        <section className="mt-10 rounded-2xl border border-white/10 bg-black/20 p-5 sm:p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-emerald-200/45">Current plan</p>
              <h3 className="mt-1 text-lg font-medium">{freePlan?.name || 'Free'} · {freePlan?.price_label || '₹0'}</h3>
            </div>
            <p className="max-w-2xl text-sm leading-6 text-emerald-50/55">
              Your free grant remains active. Limits reset on their published schedule; reads and existing resources remain available under each product’s retention policy.
            </p>
          </div>
        </section>
      </div>
    </main>
  )
}

function Metric({ icon: Icon, label, value }) {
  return (
    <div className="min-w-0 rounded-xl border border-white/10 bg-white/[0.045] p-4 backdrop-blur">
      <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-emerald-100/45">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <p className="mt-2 truncate text-lg font-medium text-emerald-50">{value}</p>
    </div>
  )
}
