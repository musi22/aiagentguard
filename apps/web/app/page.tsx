'use client';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ApiError, currentSession } from '@/lib/api';
import { Auth } from '@/components/auth';
import { Dashboard } from '@/components/dashboard';

export default function Home() {
  const me = useQuery({ queryKey: ['me'], queryFn: currentSession, retry: false });
  const [demoAuth, setDemoAuth] = useState(0);
  if (me.isLoading) return <main className="min-h-screen grid place-items-center grid-bg"><div className="text-center"><div className="mx-auto mb-4 h-9 w-9 animate-spin rounded-full border-2 border-slate-700 border-t-lime"/><p className="text-slate-400">Connecting to AgentGuard…</p></div></main>;
  if (me.error && (!(me.error instanceof ApiError) || ![401,403].includes(me.error.status))) return <main className="min-h-screen grid place-items-center p-6 grid-bg"><div className="card max-w-lg p-8"><p className="text-xs font-bold uppercase tracking-[.18em] text-amber-300">Backend unavailable</p><h1 className="mt-3 text-2xl font-semibold">AgentGuard can’t reach its API.</h1><p className="mt-3 text-slate-400">{me.error.message}</p><button className="btn btn-primary mt-6" onClick={()=>me.refetch()}>Try again</button></div></main>;
  if (!me.data) return <Auth key={demoAuth} onDone={()=>{setDemoAuth(v=>v+1); me.refetch();}}/>;
  const csrf = me.data.csrf_token || (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('agentguard_csrf') : '') || '';
  return <Dashboard me={{...me.data, csrf_token: csrf}} onLogout={()=>me.refetch()}/>;
}
