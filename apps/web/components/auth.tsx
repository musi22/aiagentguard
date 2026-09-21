'use client';
import { FormEvent, useEffect, useState } from 'react';
import { Check, Mail, ShieldCheck } from 'lucide-react';
import { API_BASE, api, Me, rememberSession } from '@/lib/api';

type AuthMode='login'|'register'|'magic';
export function Auth({ onDone }: { onDone:()=>void }) {
  const [mode,setMode]=useState<AuthMode>('login');
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const [notice,setNotice]=useState('');
  const [providers,setProviders]=useState<Record<string,boolean>>({});
  useEffect(()=>{api.get<Record<string,boolean>>('/auth/providers').then(setProviders).catch(()=>setProviders({}))},[]);
  async function submit(e:FormEvent<HTMLFormElement>){
    e.preventDefault();setBusy(true);setError('');setNotice('');
    const form=new FormData(e.currentTarget);
    try {
      if(mode==='magic'){
        const result=await api.post<{message:string;development_token?:string}>('/auth/magic-link',{email:String(form.get('email'))});
        setNotice(result.message);
        if(result.development_token) location.assign(`/auth/magic/?token=${encodeURIComponent(result.development_token)}`);
        return;
      }
      const payload:Record<string,string>={email:String(form.get('email')),password:String(form.get('password'))};
      if(mode==='register'){payload.name=String(form.get('name'));payload.organization_name=String(form.get('organization_name'))}
      const result=await api.post<Me>(`/auth/${mode}`,payload);
      rememberSession(result);onDone();
    } catch(err){setError(err instanceof Error?err.message:'Authentication failed')} finally{setBusy(false)}
  }
  const set=(value:AuthMode)=>{setMode(value);setError('');setNotice('')};
  return <main className="min-h-screen grid-bg lg:grid lg:grid-cols-[1.1fr_.9fr]">
    <section className="hidden lg:flex flex-col justify-between p-12 xl:p-20 border-r border-slate-800 bg-[radial-gradient(circle_at_20%_10%,rgba(158,240,26,.12),transparent_38%)]">
      <Brand/><div><p className="text-lime text-sm font-bold tracking-[.2em] uppercase">Runtime governance</p><h1 className="mt-5 text-5xl xl:text-6xl font-semibold tracking-tight max-w-3xl">Every agent action.<br/>Inside your guardrails.</h1><p className="mt-6 max-w-xl text-lg leading-8 text-slate-400">Policy decisions, human approvals, credentials, budgets, and audit evidence in one control plane.</p></div>
      <div className="flex gap-8 text-sm text-slate-400">{['Policy before execution','Short-lived credentials','Complete audit trail'].map(x=><span className="flex items-center gap-2" key={x}><Check size={15} className="text-lime"/>{x}</span>)}</div>
    </section>
    <section className="min-h-screen flex items-center justify-center p-6"><div className="w-full max-w-md"><div className="lg:hidden mb-10"><Brand/></div>
      <p className="text-sm text-slate-400">{mode==='login'?'Welcome back':mode==='register'?'Create your secure control plane':'Passwordless sign in'}</p>
      <h2 className="mt-2 text-3xl font-semibold">{mode==='login'?'Sign in':mode==='register'?'Start protecting agents':'Email me a secure link'}</h2>
      <form onSubmit={submit} className="mt-8 space-y-4">
        {mode==='register'&&<><Field name="name" label="Your name"/><Field name="organization_name" label="Organization"/></>}
        <Field name="email" label="Work email" type="email"/>
        {mode!=='magic'&&<Field name="password" label="Password" type="password" minLength={mode==='register'?12:1}/>}
        {error&&<p role="alert" className="rounded-lg border border-red-900 bg-red-950/40 p-3 text-sm text-red-300">{error}</p>}
        {notice&&<p role="status" className="rounded-lg border border-lime/30 bg-lime/5 p-3 text-sm text-lime">{notice}</p>}
        <button disabled={busy} className="btn btn-primary w-full">{busy?'Please wait…':mode==='login'?'Sign in':mode==='register'?'Create organization':'Send magic link'}</button>
      </form>
      <div className="mt-5 flex flex-wrap gap-4 text-sm text-slate-400">
        {mode!=='login'&&<button onClick={()=>set('login')}>Use password</button>}
        {mode==='login'&&<button onClick={()=>set('register')}>Create account</button>}
        {mode!=='magic'&&<button onClick={()=>set('magic')} className="flex items-center gap-1"><Mail size={14}/>Magic link</button>}
      </div>
      <div className="my-7 flex items-center gap-3 text-xs text-slate-600"><span className="h-px flex-1 bg-slate-800"/>SSO<span className="h-px flex-1 bg-slate-800"/></div>
      <div className="grid grid-cols-3 gap-2">{['microsoft','google','github'].map(p=>{const ok=providers[p]===true;return <button type="button" key={p} disabled={!ok} onClick={()=>ok&&location.assign(`${API_BASE}/api/v1/auth/oauth/${p}/start`)} title={ok?`Continue with ${p}`:`${p} is not configured`} className="btn btn-secondary !px-2 text-xs capitalize disabled:cursor-not-allowed disabled:opacity-35">{p}</button>})}</div>
      <p className="mt-5 text-xs text-slate-600">SSO options become available when configured by an administrator.</p>
    </div></section>
  </main>
}
function Brand(){return <div className="flex items-center gap-3"><span className="grid h-10 w-10 place-items-center rounded-xl bg-lime text-ink"><ShieldCheck size={22}/></span><span className="font-semibold text-xl">AgentGuard</span></div>}
function Field({name,label,type='text',minLength}:{name:string;label:string;type?:string;minLength?:number}){return <label><span className="label">{label}</span><input required name={name} type={type} minLength={minLength} className="field"/></label>}
