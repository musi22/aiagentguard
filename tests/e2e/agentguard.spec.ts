import { expect, test, type Page } from '@playwright/test';

const me={user:{id:'u1',email:'owner@example.com',name:'Avery Stone'},organization:{id:'o1',name:'Acme Security',plan:'free'},role:'owner',csrf_token:null,workspaces:[{id:'w1',name:'Default',environment:'development'}],teams:[]};
const json=(body:unknown,status=200)=>({status,contentType:'application/json',body:JSON.stringify(body),headers:{'access-control-allow-origin':'http://localhost:3000','access-control-allow-credentials':'true'}});

async function mockApi(page:Page,authenticated:boolean) {
  await page.route('http://localhost:8000/api/v1/**',async route=>{
    const url=new URL(route.request().url()); const path=url.pathname.replace('/api/v1','');
    if(path==='/auth/me') return route.fulfill(authenticated?json(me):json({detail:'Unauthenticated'},401));
    if(path==='/auth/refresh') return route.fulfill(json({detail:'Expired'},401));
    if(path==='/auth/providers') return route.fulfill(json({microsoft:false,google:false,github:false}));
    if(path==='/overview') return route.fulfill(json({active_agents:0,protected_actions:0,blocked_actions:0,pending_approvals:0,high_risk_actions:0,monthly_spend_minor:0,security_score:null,decision_counts:{},daily_actions:[]}));
    if(path==='/agents'&&route.request().method()==='GET') return route.fulfill(json([{id:'a1',name:'Operations agent',framework:'custom',model_provider:'openai',environment:'development',status:'active'}]));
    if(path==='/tools') return route.fulfill(json([{id:'t1',name:'github.create_issue',environment:'development'}]));
    if(path==='/agents/a1/credentials') {
      expect(route.request().headers()['x-csrf-token']).toBe('csrf-test');
      expect(route.request().postDataJSON()).toEqual({environment:'development',expires_in_days:30,tools:['github.create_issue']});
      return route.fulfill(json({api_key:'ag_dev_secret-once',credential:{id:'c1'}} ,201));
    }
    return route.fulfill(json([]));
  });
}

test('shows real unauthenticated sign-in and configuration-aware SSO',async({page})=>{
  await mockApi(page,false); await page.goto('/');
  await expect(page.getByRole('heading',{name:'Sign in'})).toBeVisible();
  await expect(page.getByRole('button',{name:'microsoft'})).toBeDisabled();
  await page.getByRole('button',{name:/magic link/i}).click();
  await expect(page.getByRole('heading',{name:'Email me a secure link'})).toBeVisible();
});

test('loads dashboard data and issues a tool-scoped credential once',async({page})=>{
  await page.addInitScript(()=>sessionStorage.setItem('agentguard_csrf','csrf-test'));
  await mockApi(page,true); await page.goto('/');
  await expect(page.getByRole('heading',{name:'Overview'})).toBeVisible();
  await expect(page.getByText('Active agents')).toBeVisible();
  await page.getByRole('button',{name:'Agents'}).click();
  await expect(page.getByText('Operations agent')).toBeVisible();
  await page.getByRole('button',{name:'Issue credential'}).click();
  await page.getByLabel('github.create_issue').check();
  await page.getByRole('button',{name:'Generate credential'}).click();
  await expect(page.getByText('ag_dev_secret-once')).toBeVisible();
  await expect(page.getByText('it will not be shown again')).toBeVisible();
});
