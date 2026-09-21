'use client';
import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api, Me, rememberSession } from '@/lib/api';

export default function MagicLinkPage() {
  const [error,setError]=useState('');
  useEffect(()=>{
    const token=new URLSearchParams(location.search).get('token');
    if(!token){setError('This sign-in link is missing its token.');return}
    api.post<Me>('/auth/magic-link/consume',{token})
      .then(me=>{rememberSession(me);location.replace('/')})
      .catch(err=>setError(err instanceof Error?err.message:'This sign-in link could not be used.'));
  },[]);
  return <main className="grid min-h-screen place-items-center p-6 grid-bg"><div className="card w-full max-w-md p-8 text-center"><span className="mx-auto grid h-12 w-12 place-items-center rounded-xl bg-lime text-ink"><ShieldCheck/></span><h1 className="mt-5 text-2xl font-semibold">Signing you in securely</h1>{error?<><p role="alert" className="mt-4 text-red-300">{error}</p><a className="btn btn-secondary mt-6" href="/">Return to sign in</a></>:<><div className="mx-auto mt-6 h-7 w-7 animate-spin rounded-full border-2 border-slate-700 border-t-lime"/><p className="mt-4 text-sm text-slate-400">Verifying your one-time link…</p></>}</div></main>
}
