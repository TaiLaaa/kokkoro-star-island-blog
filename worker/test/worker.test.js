import test from 'node:test';
import assert from 'node:assert/strict';
import { handleRequest } from '../src/app.js';

class MemoryDB {
  constructor(){ this.posts=[]; this.attempts=[]; this.nextId=1; }
  prepare(sql){ return new Statement(this, sql); }
}
class Statement {
  constructor(db,sql){ this.db=db; this.sql=sql.replace(/\s+/g,' ').trim(); this.args=[]; }
  bind(...args){ this.args=args; return this; }
  async all(){
    if(this.sql.includes("WHERE status='published'")) return {results:this.db.posts.filter(p=>p.status==='published').sort((a,b)=>b.id-a.id)};
    if(this.sql.includes('FROM posts ORDER BY updated_at')) return {results:[...this.db.posts].sort((a,b)=>b.id-a.id)};
    throw new Error('unsupported all '+this.sql);
  }
  async first(){
    if(this.sql.includes('FROM login_attempts')){ const [ip,cutoff]=this.args; return {count:this.db.attempts.filter(x=>x.ip===ip&&x.attempted_at>=cutoff).length}; }
    if(this.sql.includes('WHERE id=?')) return this.db.posts.find(p=>p.id===Number(this.args[0]))||null;
    throw new Error('unsupported first '+this.sql);
  }
  async run(){
    if(this.sql.startsWith('DELETE FROM login_attempts WHERE attempted_at')){ const [cutoff]=this.args; this.db.attempts=this.db.attempts.filter(x=>x.attempted_at>=cutoff); return {meta:{changes:1}}; }
    if(this.sql.startsWith('DELETE FROM login_attempts WHERE ip')){ const [ip]=this.args; this.db.attempts=this.db.attempts.filter(x=>x.ip!==ip); return {meta:{changes:1}}; }
    if(this.sql.startsWith('INSERT INTO login_attempts')){ const [ip,at]=this.args; this.db.attempts.push({ip,attempted_at:at}); return {meta:{changes:1}}; }
    if(this.sql.startsWith('INSERT INTO posts')){
      const [title,category,content,status,created_at,updated_at,published_at,cover]=this.args;
      const id=this.db.nextId++; const p={id,slug:null,title,category,content,status,created_at,updated_at,published_at,cover}; this.db.posts.push(p); return {meta:{last_row_id:id}};
    }
    if(this.sql.startsWith('UPDATE posts SET slug=')){ const [slug,id]=this.args; this.db.posts.find(p=>p.id===Number(id)).slug=slug; return {meta:{changes:1}}; }
    if(this.sql.startsWith('UPDATE posts SET title=')){
      const [title,category,content,status,updated_at,published_at,cover,id]=this.args; const p=this.db.posts.find(x=>x.id===Number(id)); Object.assign(p,{title,category,content,status,updated_at,published_at,cover}); return {meta:{changes:1}};
    }
    if(this.sql.startsWith('DELETE FROM posts')){ const id=Number(this.args[0]); this.db.posts=this.db.posts.filter(p=>p.id!==id); return {meta:{changes:1}}; }
    throw new Error('unsupported run '+this.sql);
  }
}
const env=()=>({DB:new MemoryDB(),ADMIN_PASSWORD:'correct horse',SESSION_SECRET:'test-secret'});
const req=(path,init={})=>new Request('https://example.com'+path,{...init,headers:{'content-type':'application/json',...(init.headers||{})}});
const body=r=>r.status===204?null:r.json();
async function login(e){const r=await handleRequest(req('/api/login',{method:'POST',body:JSON.stringify({password:'correct horse'})}),e);assert.equal(r.status,200);return r.headers.get('set-cookie').split(';')[0];}

test('login rejects bad password and signed session authenticates',async()=>{const e=env();let r=await handleRequest(req('/api/login',{method:'POST',body:'{"password":"wrong"}'}),e);assert.equal(r.status,401);const cookie=await login(e);r=await handleRequest(req('/api/session',{headers:{cookie}}),e);assert.deepEqual(await body(r),{authenticated:true});});
test('anonymous cannot mutate posts',async()=>{const e=env();for(const [method,path] of [['POST','/api/posts'],['PUT','/api/posts/1'],['DELETE','/api/posts/1']])assert.equal((await handleRequest(req(path,{method,body:method==='DELETE'?undefined:'{}'}),e)).status,401);});
test('admin can create publish list update draft and delete',async()=>{const e=env(),cookie=await login(e);const post={title:'第一颗新星',category:'随笔',content:'第一段\n\n第二段',status:'published',cover:'/assets/hero-anime.jpg'};let r=await handleRequest(req('/api/posts',{method:'POST',headers:{cookie},body:JSON.stringify(post)}),e);assert.equal(r.status,201);const made=await body(r);assert.equal(made.slug,'post-1');r=await handleRequest(req('/api/posts'),e);assert.equal((await body(r))[0].title,post.title);r=await handleRequest(req('/api/posts/1',{method:'PUT',headers:{cookie},body:JSON.stringify({...post,title:'更新',status:'draft'})}),e);assert.equal((await body(r)).status,'draft');assert.deepEqual(await body(await handleRequest(req('/api/posts'),e)),[]);assert.equal((await body(await handleRequest(req('/api/admin/posts',{headers:{cookie}}),e)))[0].title,'更新');assert.equal((await handleRequest(req('/api/posts/1',{method:'DELETE',headers:{cookie}}),e)).status,204);});
test('validation rejects unsafe cover and invalid fields',async()=>{const e=env(),cookie=await login(e);for(const p of [{title:'',content:'x',status:'published'},{title:'x',content:'',status:'published'},{title:'x',content:'x',status:'bad'},{title:'x',content:'x',status:'published',cover:'https://evil.test/a.jpg'}])assert.equal((await handleRequest(req('/api/posts',{method:'POST',headers:{cookie},body:JSON.stringify(p)}),e)).status,422);});
test('logout expires cookie and forged session fails',async()=>{const e=env(),cookie=await login(e);let forged=cookie.replace(/.$/,'x');assert.deepEqual(await body(await handleRequest(req('/api/session',{headers:{cookie:forged}}),e)),{authenticated:false});let r=await handleRequest(req('/api/logout',{method:'POST',headers:{cookie}}),e);assert.match(r.headers.get('set-cookie'),/Max-Age=0/);});
test('five failed logins block the same Cloudflare peer but not a different peer',async()=>{const e=env();for(let i=0;i<5;i++){const r=await handleRequest(req('/api/login',{method:'POST',headers:{'cf-connecting-ip':'203.0.113.7'},body:'{"password":"wrong"}'}),e);assert.equal(r.status,401);}let r=await handleRequest(req('/api/login',{method:'POST',headers:{'cf-connecting-ip':'203.0.113.7'},body:'{"password":"wrong"}'}),e);assert.equal(r.status,429);assert.equal(r.headers.get('retry-after'),'300');r=await handleRequest(req('/api/login',{method:'POST',headers:{'cf-connecting-ip':'198.51.100.9'},body:'{"password":"wrong"}'}),e);assert.equal(r.status,401);});
