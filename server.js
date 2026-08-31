require("dotenv").config();
const express=require("express"),cors=require("cors"),helmet=require("helmet"),rateLimit=require("express-rate-limit");
const crypto=require("crypto"),axios=require("axios"),jwt=require("jsonwebtoken");
const db=require("./db");const {sha,otp,token,hashPassword,checkPassword,sign}=require("./auth");
require("./migrate");

const app=express();
app.set("trust proxy",1);
app.use(helmet({crossOriginResourcePolicy:false}));
app.use(cors({origin:process.env.CORS_ORIGIN||true}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:false}));
app.use(express.static("public"));
app.use("/api/",rateLimit({windowMs:15*60*1000,limit:250,standardHeaders:true,legacyHeaders:false}));

const OTP_TTL=Number(process.env.TELEGRAM_OTP_TTL_SECONDS||300);
const now=()=>new Date().toISOString();
const uname=x=>String(x||"").trim().replace(/^@/,"").toLowerCase();
const safeMoney=x=>{const n=Number(x);if(!Number.isFinite(n)||n<=0||n>100000000)throw Error("Invalid amount");return Math.round(n*100)/100};
const user=id=>db.prepare(`SELECT id,public_id,username,email,phone_e164,telegram_username,telegram_chat_id,telegram_user_id,telegram_verified,role,status,balance,created_at FROM users WHERE id=?`).get(id);
const setting=k=>db.prepare("SELECT value FROM settings WHERE key=?").get(k)?.value||"";
const audit=(actor,action,type,id,meta,req)=>db.prepare(`INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,metadata,ip,user_agent) VALUES(?,?,?,?,?,?,?)`).run(actor||null,action,type||null,id==null?null:String(id),meta?JSON.stringify(meta):null,req?.ip||null,req?.headers["user-agent"]||null);

function createChallenge(userId,purpose){
  const t=token(),code=otp(),expires=new Date(Date.now()+OTP_TTL*1000).toISOString();
  db.prepare(`INSERT INTO otp_challenges(token,user_id,purpose,otp_hash,expires_at) VALUES(?,?,?,?,?)`).run(t,userId,purpose,sha(code),expires);
  return {token:t,code,expires};
}
async function tgSend(chat,text){
  if(!process.env.TELEGRAM_BOT_TOKEN) throw Error("Telegram bot is not configured");
  return axios.post(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,{chat_id:chat,text,parse_mode:"HTML"},{timeout:10000});
}
function bearer(req){
  const h=req.headers.authorization||"";return h.startsWith("Bearer ")?h.slice(7):null;
}
function auth(req,res,next){
  try{
    const t=bearer(req);if(!t)throw Error();
    const p=jwt.verify(t,process.env.JWT_SECRET||"development-only-change-me");
    const u=user(p.sub),s=db.prepare("SELECT * FROM sessions WHERE id=? AND user_id=? AND revoked_at IS NULL").get(p.session,p.sub);
    if(!u||u.status!=="active"||!s||new Date(s.expires_at)<new Date())throw Error();
    req.user=u;req.session=s;next();
  }catch{res.status(401).json({error:"Authentication required"});}
}
const roles=(...r)=>(req,res,next)=>r.includes(req.user.role)?next():res.status(403).json({error:"Permission denied"});
function perm(p){return (req,res,next)=>{if(req.user.role==="owner")return next();const x=db.prepare("SELECT 1 FROM admin_permissions WHERE admin_id=? AND permission=?").get(req.user.id,p);return x?next():res.status(403).json({error:"Permission denied"});}}
function issueSession(u,req){
  const raw=token(),hash=sha(raw),expires=new Date(Date.now()+2*60*60*1000).toISOString();
  const info=db.prepare("INSERT INTO sessions(user_id,token_hash,expires_at,ip,user_agent) VALUES(?,?,?,?,?)").run(u.id,hash,expires,req.ip,req.headers["user-agent"]||"");
  const payload={...u,session_id:info.lastInsertRowid};return {jwt:sign(payload),session_id:info.lastInsertRowid};
}
function idem(req,userId,route){
  const k=req.headers["idempotency-key"];if(!k)return null;
  const found=db.prepare("SELECT response_json FROM idempotency_keys WHERE user_id=? AND idem_key=? AND route=?").get(userId,k,route);
  return found?JSON.parse(found.response_json):null;
}
function saveIdem(req,userId,route,response){const k=req.headers["idempotency-key"];if(k)db.prepare("INSERT OR IGNORE INTO idempotency_keys(user_id,idem_key,route,response_json) VALUES(?,?,?,?,?)").run(userId,k,route,JSON.stringify(response));}

app.get("/api/health",(q,s)=>s.json({ok:true,service:"TXG Gateway",version:"2.0.0"}));

app.post("/api/auth/register",async(req,res)=>{
 try{
  const username=uname(req.body.username),email=String(req.body.email||"").trim().toLowerCase(),phone=String(req.body.phone_e164||"").trim(),password=String(req.body.password||"");
  if(!/^[a-z0-9_]{3,32}$/.test(username))throw Error("Username must be 3-32 characters.");
  if(!/^\S+@\S+\.\S+$/.test(email))throw Error("Invalid email.");
  if(!/^\+[1-9]\d{7,14}$/.test(phone))throw Error("Use mobile number in E.164 format, e.g. +919876543210.");
  if(password.length<10)throw Error("Password must be at least 10 characters.");
  if(db.prepare("SELECT id FROM users WHERE username=? OR email=? OR phone_e164=?").get(username,email,phone))throw Error("Username, email or mobile already exists.");
  const publicId="TXG-"+crypto.randomBytes(6).toString("hex").toUpperCase();
  const r=db.prepare("INSERT INTO users(public_id,username,email,phone_e164,password_hash) VALUES(?,?,?,?,?)").run(publicId,username,email,phone,hashPassword(password));
  const ch=createChallenge(r.lastInsertRowid,"register");
  audit(r.lastInsertRowid,"register_challenge_created","user",r.lastInsertRowid,{public_id:publicId},req);
  const tg=process.env.TELEGRAM_BOT_USERNAME?`https://t.me/${process.env.TELEGRAM_BOT_USERNAME}?start=${ch.token}`:"";
  res.json({ok:true,challenge:ch.token,telegram_url:tg,expires_at:ch.expires,message:"Open Telegram and press Start. OTP is generated only after Start."});
 }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/auth/verify-register",(req,res)=>{
 try{
  const c=db.prepare("SELECT * FROM otp_challenges WHERE token=? AND purpose='register' AND verified_at IS NULL").get(String(req.body.challenge||""));
  if(!c||!c.started_at||new Date(c.expires_at)<new Date())throw Error("Open the Telegram bot and press Start first, or request a new OTP.");
  if(c.attempts>=c.max_attempts)throw Error("Too many OTP attempts. Request a new OTP.");
  const code=String(req.body.otp||"");db.prepare("UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?").run(c.id);
  if(sha(code)!==c.otp_hash)throw Error("Incorrect OTP.");
  db.prepare("UPDATE otp_challenges SET verified_at=? WHERE id=?").run(now(),c.id);
  db.prepare("UPDATE users SET telegram_verified=1 WHERE id=?").run(c.user_id);
  const u=user(c.user_id),session=issueSession(u,req);audit(u.id,"register_verified","user",u.id,{},req);
  res.json({ok:true,token:session.jwt,user:user(u.id)});
 }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/auth/login",(req,res)=>{
 try{
  const identity=String(req.body.username||"").trim().toLowerCase(),password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE username=? OR email=? OR phone_e164=?").get(identity,identity,identity);
  if(!u||u.status!=="active"||!checkPassword(password,u.password_hash))throw Error("Invalid login.");
  if(!u.telegram_verified||!u.telegram_chat_id)throw Error("Telegram is not linked. Complete registration verification first.");
  const c=createChallenge(u.id,"login");db.prepare("UPDATE otp_challenges SET started_at=?,telegram_chat_id=? WHERE token=?").run(now(),u.telegram_chat_id,c.token);
  tgSend(u.telegram_chat_id,`<b>TXG Gateway Login OTP</b>\n\nYour OTP: <code>${c.code}</code>\n\nExpires in ${Math.ceil(OTP_TTL/60)} minutes.`).catch(e=>console.error("Telegram:",e.message));
  res.json({ok:true,challenge:c.token,expires_at:c.expires});
 }catch(e){res.status(401).json({error:e.message});}
});

app.post("/api/auth/verify-login",(req,res)=>{
 try{
  const c=db.prepare("SELECT * FROM otp_challenges WHERE token=? AND purpose='login' AND verified_at IS NULL").get(String(req.body.challenge||""));
  if(!c||!c.started_at||new Date(c.expires_at)<new Date())throw Error("OTP expired or not started.");
  if(c.attempts>=c.max_attempts)throw Error("Too many attempts. Login again for a new OTP.");
  db.prepare("UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?").run(c.id);
  if(sha(String(req.body.otp||""))!==c.otp_hash)throw Error("Incorrect OTP.");
  db.prepare("UPDATE otp_challenges SET verified_at=? WHERE id=?").run(now(),c.id);
  const u=user(c.user_id),session=issueSession(u,req);audit(u.id,"login_verified","user",u.id,{},req);
  res.json({ok:true,token:session.jwt,user:u});
 }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/auth/logout",auth,(req,res)=>{db.prepare("UPDATE sessions SET revoked_at=? WHERE id=?").run(now(),req.session.id);res.json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json({user:user(req.user.id)}));

app.get("/api/dashboard",auth,(req,res)=>{
 const u=user(req.user.id),deposits=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM deposits WHERE user_id=? AND status='approved'").get(u.id).s;
 const withdrawals=db.prepare("SELECT COALESCE(SUM(amount),0) s FROM withdrawals WHERE user_id=? AND status='approved'").get(u.id).s;
 res.json({balance:u.balance,deposits,withdrawals,public_id:u.public_id});
});

app.get("/api/payment-info",(req,res)=>res.json({upi_id:setting("upi_id"),qr_image_url:setting("qr_image_url"),deposit_mode:setting("deposit_mode"),ads_text:setting("ads_text"),channel_url:setting("channel_url")}));

app.post("/api/deposits",auth,(req,res)=>{
 try{
  const cached=idem(req,req.user.id,"POST:/api/deposits");if(cached)return res.json(cached);
  const amount=safeMoney(req.body.amount),reference=String(req.body.reference||"").trim().slice(0,120);
  const r=db.prepare("INSERT INTO deposits(user_id,amount,reference,provider) VALUES(?,?,?,?)").run(req.user.id,amount,reference,setting("deposit_mode")||"manual");
  audit(req.user.id,"deposit_created","deposit",r.lastInsertRowid,{amount,reference},req);
  const out={ok:true,id:r.lastInsertRowid,status:"pending"};saveIdem(req,req.user.id,"POST:/api/deposits",out);res.json(out);
 }catch(e){res.status(400).json({error:e.message});}
});

function payment(senderId,recipientKey,amount,reference){
 const rec=db.prepare("SELECT * FROM users WHERE status='active' AND (public_id=? OR username=? OR CAST(id AS TEXT)=?)").get(String(recipientKey||""),uname(recipientKey),String(recipientKey||""));
 if(!rec)throw Error("Recipient not found. Use TXG User ID or username.");
 if(rec.id===senderId)throw Error("You cannot pay yourself.");
 const ref=reference||"PAY-"+crypto.randomBytes(8).toString("hex").toUpperCase();
 return db.transaction(()=>{
  const s=db.prepare("SELECT balance FROM users WHERE id=?").get(senderId);if(s.balance<amount)throw Error("Insufficient balance.");
  const sb=Math.round((s.balance-amount)*100)/100,rb=Math.round((rec.balance+amount)*100)/100;
  db.prepare("UPDATE users SET balance=?,updated_at=? WHERE id=?").run(sb,now(),senderId);
  db.prepare("UPDATE users SET balance=?,updated_at=? WHERE id=?").run(rb,now(),rec.id);
  db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,reference,description) VALUES(?,?,?,?,?,?)").run(senderId,"payment",-amount,sb,ref,"Payment to "+rec.public_id);
  db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,reference,description) VALUES(?,?,?,?,?,?)").run(rec.id,"payment_received",amount,rb,ref,"Payment from "+user(senderId).public_id);
  db.prepare("INSERT INTO transactions(user_id,kind,amount,counterparty_user_id,reference) VALUES(?,?,?,?,?)").run(senderId,"payment_sent",-amount,rec.id,ref);
  db.prepare("INSERT INTO transactions(user_id,kind,amount,counterparty_user_id,reference) VALUES(?,?,?,?,?)").run(rec.id,"payment_received",amount,senderId,ref);
  return {recipient:rec,reference:ref};
 })();
}
app.post("/api/payments",auth,(req,res)=>{
 try{
  const cached=idem(req,req.user.id,"POST:/api/payments");if(cached)return res.json(cached);
  const amount=safeMoney(req.body.amount),out=payment(req.user.id,req.body.recipient,amount,String(req.body.reference||"").slice(0,100));
  audit(req.user.id,"payment_sent","transaction",out.reference,{amount,to:out.recipient.public_id},req);
  const response={ok:true,reference:out.reference,recipient:out.recipient.public_id};saveIdem(req,req.user.id,"POST:/api/payments",response);res.json(response);
 }catch(e){res.status(400).json({error:e.message});}
});

app.post("/api/withdrawals",auth,(req,res)=>{
 try{
  const amount=safeMoney(req.body.amount),upi=String(req.body.upi_id||"").trim().slice(0,100);
  if(!upi)throw Error("UPI ID is required.");
  const min=Number(setting("withdraw_min")||1),max=Number(setting("withdraw_max")||100000);
  if(amount<min||amount>max)throw Error(`Withdrawal must be between ₹${min} and ₹${max}.`);
  const out=db.transaction(()=>{
   const u=db.prepare("SELECT balance FROM users WHERE id=?").get(req.user.id);if(u.balance<amount)throw Error("Insufficient balance.");
   const nb=Math.round((u.balance-amount)*100)/100;db.prepare("UPDATE users SET balance=?,updated_at=? WHERE id=?").run(nb,now(),req.user.id);
   const w=db.prepare("INSERT INTO withdrawals(user_id,amount,upi_id) VALUES(?,?,?)").run(req.user.id,amount,upi);
   db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,reference,description) VALUES(?,?,?,?,?,?)").run(req.user.id,"withdrawal_hold",-amount,nb,"WD-"+w.lastInsertRowid,"Withdrawal reserved pending approval");
   db.prepare("INSERT INTO transactions(user_id,kind,amount,reference,status) VALUES(?,?,?,?,?)").run(req.user.id,"withdrawal",-amount,"WD-"+w.lastInsertRowid,"pending");
   return w.lastInsertRowid;
  })();
  audit(req.user.id,"withdrawal_created","withdrawal",out,{amount},req);res.json({ok:true,id:out,status:"pending"});
 }catch(e){res.status(400).json({error:e.message});}
});

app.get("/api/transactions",auth,(req,res)=>res.json({transactions:db.prepare(`SELECT t.*,u.username counterparty_username,u.public_id counterparty_public_id FROM transactions t LEFT JOIN users u ON u.id=t.counterparty_user_id WHERE t.user_id=? ORDER BY t.id DESC LIMIT 200`).all(req.user.id)}));
app.get("/api/ledger",auth,(req,res)=>res.json({ledger:db.prepare("SELECT * FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 200").all(req.user.id)}));

app.get("/api/keys",auth,(req,res)=>res.json({keys:db.prepare("SELECT id,name,prefix,active,created_at,last_used_at FROM api_keys WHERE user_id=? ORDER BY id DESC").all(req.user.id)}));
app.post("/api/keys",auth,(req,res)=>{
 try{const raw="txg_live_"+crypto.randomBytes(32).toString("hex"),r=db.prepare("INSERT INTO api_keys(user_id,name,key_hash,prefix) VALUES(?,?,?,?)").run(req.user.id,String(req.body.name||"Default").slice(0,60),sha(raw),raw.slice(0,20));audit(req.user.id,"api_key_created","api_key",r.lastInsertRowid,{},req);res.json({ok:true,key:raw,id:r.lastInsertRowid})}catch(e){res.status(400).json({error:e.message})}
});
app.delete("/api/keys/:id",auth,(req,res)=>{db.prepare("UPDATE api_keys SET active=0 WHERE id=? AND user_id=?").run(req.params.id,req.user.id);audit(req.user.id,"api_key_revoked","api_key",req.params.id,{},req);res.json({ok:true})});

function apiKeyAuth(req,res,next){
 const h=req.headers.authorization||"";if(!h.startsWith("Bearer txg_live_"))return res.status(401).json({error:"API key required"});
 const raw=h.slice(7),k=db.prepare("SELECT * FROM api_keys WHERE key_hash=? AND active=1").get(sha(raw));if(!k)return res.status(401).json({error:"Invalid API key"});
 const u=user(k.user_id);if(!u||u.status!=="active")return res.status(403).json({error:"Account unavailable"});
 db.prepare("UPDATE api_keys SET last_used_at=? WHERE id=?").run(now(),k.id);req.user=u;next();
}
app.post("/api/v1/payments",apiKeyAuth,(req,res)=>{try{const amount=safeMoney(req.body.amount),out=payment(req.user.id,req.body.recipient,amount,String(req.body.reference||"").slice(0,100));res.json({ok:true,reference:out.reference,recipient:out.recipient.public_id})}catch(e){res.status(400).json({error:e.message})}});

// Admin
app.get("/api/admin/stats",auth,roles("admin","owner"),perm("dashboard"),(req,res)=>res.json({
 users:db.prepare("SELECT COUNT(*) c FROM users WHERE role='user'").get().c,
 depositsPending:db.prepare("SELECT COUNT(*) c FROM deposits WHERE status='pending'").get().c,
 withdrawalsPending:db.prepare("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'").get().c,
 volume:db.prepare("SELECT COALESCE(SUM(ABS(amount)),0) s FROM transactions").get().s
}));
app.get("/api/admin/users",auth,roles("admin","owner"),perm("users"),(req,res)=>res.json({users:db.prepare("SELECT id,public_id,username,email,phone_e164,telegram_username,telegram_verified,role,status,balance,created_at FROM users ORDER BY id DESC LIMIT 1000").all()}));
app.get("/api/admin/deposits",auth,roles("admin","owner"),perm("deposits"),(req,res)=>res.json({deposits:db.prepare("SELECT d.*,u.username,u.public_id FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.id DESC LIMIT 500").all()}));
app.get("/api/admin/withdrawals",auth,roles("admin","owner"),perm("withdrawals"),(req,res)=>res.json({withdrawals:db.prepare("SELECT w.*,u.username,u.public_id FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC LIMIT 500").all()}));
app.get("/api/admin/transactions",auth,roles("admin","owner"),perm("transactions"),(req,res)=>res.json({transactions:db.prepare("SELECT t.*,u.username,c.username counterparty_username FROM transactions t JOIN users u ON u.id=t.user_id LEFT JOIN users c ON c.id=t.counterparty_user_id ORDER BY t.id DESC LIMIT 1000").all()}));

app.post("/api/admin/deposits/:id/review",auth,roles("admin","owner"),perm("deposits"),(req,res)=>{
 try{const action=String(req.body.action||""),note=String(req.body.note||"").slice(0,500);if(!["approve","reject"].includes(action))throw Error("Invalid action");
  db.transaction(()=>{const d=db.prepare("SELECT * FROM deposits WHERE id=?").get(req.params.id);if(!d||d.status!=="pending")throw Error("Deposit is not pending.");
   if(action==="approve"){const u=db.prepare("SELECT balance FROM users WHERE id=?").get(d.user_id),nb=Math.round((u.balance+d.amount)*100)/100;db.prepare("UPDATE users SET balance=?,updated_at=? WHERE id=?").run(nb,now(),d.user_id);db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,reference,description) VALUES(?,?,?,?,?,?)").run(d.user_id,"deposit",d.amount,nb,"DEP-"+d.id,"Deposit approved");db.prepare("INSERT INTO transactions(user_id,kind,amount,reference) VALUES(?,?,?,?)").run(d.user_id,"deposit",d.amount,"DEP-"+d.id)}
   db.prepare("UPDATE deposits SET status=?,admin_note=?,reviewed_at=?,reviewed_by=? WHERE id=?").run(action==="approve"?"approved":"rejected",note,now(),req.user.id,d.id);
  })();audit(req.user.id,"deposit_"+action,"deposit",req.params.id,{note},req);res.json({ok:true});
 }catch(e){res.status(400).json({error:e.message})}
});
app.post("/api/admin/withdrawals/:id/review",auth,roles("admin","owner"),perm("withdrawals"),(req,res)=>{
 try{const action=String(req.body.action||""),note=String(req.body.note||"").slice(0,500);if(!["approve","reject"].includes(action))throw Error("Invalid action");
  db.transaction(()=>{const w=db.prepare("SELECT * FROM withdrawals WHERE id=?").get(req.params.id);if(!w||w.status!=="pending")throw Error("Withdrawal is not pending.");
   if(action==="reject"){const u=db.prepare("SELECT balance FROM users WHERE id=?").get(w.user_id),nb=Math.round((u.balance+w.amount)*100)/100;db.prepare("UPDATE users SET balance=?,updated_at=? WHERE id=?").run(nb,now(),w.user_id);db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,reference,description) VALUES(?,?,?,?,?,?)").run(w.user_id,"withdrawal_refund",w.amount,nb,"WDR-"+w.id,"Withdrawal rejected and refunded")}
   db.prepare("UPDATE withdrawals SET status=?,admin_note=?,reviewed_at=?,reviewed_by=? WHERE id=?").run(action==="approve"?"approved":"rejected",note,now(),req.user.id,w.id);db.prepare("UPDATE transactions SET status=? WHERE reference=?").run(action==="approve"?"completed":"rejected","WD-"+w.id);
  })();audit(req.user.id,"withdrawal_"+action,"withdrawal",req.params.id,{note},req);res.json({ok:true});
 }catch(e){res.status(400).json({error:e.message})}
});

app.get("/api/admin/settings",auth,roles("admin","owner"),perm("settings"),(req,res)=>res.json({upi_id:setting("upi_id"),qr_image_url:setting("qr_image_url"),ads_text:setting("ads_text"),channel_url:setting("channel_url"),alert_bot_enabled:setting("alert_bot_enabled"),alert_chat_id:setting("alert_chat_id"),deposit_mode:setting("deposit_mode"),withdraw_min:setting("withdraw_min"),withdraw_max:setting("withdraw_max")}));
app.post("/api/admin/settings",auth,roles("owner"),(req,res)=>{for(const k of ["upi_id","qr_image_url","ads_text","channel_url","alert_bot_enabled","alert_chat_id","deposit_mode","withdraw_min","withdraw_max"])if(k in req.body)db.prepare(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`).run(k,String(req.body[k]).slice(0,3000),now());audit(req.user.id,"settings_updated","settings","global",{keys:Object.keys(req.body)},req);res.json({ok:true})});

app.get("/api/owner/admins",auth,roles("owner"),(req,res)=>res.json({admins:db.prepare("SELECT id,username,email,phone_e164,role,status,created_at FROM users WHERE role='admin' ORDER BY id").all()}));
app.post("/api/owner/admins",auth,roles("owner"),(req,res)=>{try{const u=uname(req.body.username),e=String(req.body.email||"").trim().toLowerCase(),p=String(req.body.phone_e164||"").trim(),pw=String(req.body.password||"");if(!/^[a-z0-9_]{3,32}$/.test(u)||!/^\S+@\S+\.\S+$/.test(e)||!/^\+[1-9]\d{7,14}$/.test(p)||pw.length<10)throw Error("Invalid admin details.");if(db.prepare("SELECT id FROM users WHERE username=? OR email=? OR phone_e164=?").get(u,e,p))throw Error("Username, email or mobile already exists.");const id=db.prepare("INSERT INTO users(public_id,username,email,phone_e164,password_hash,role) VALUES(?,?,?,?,?,'admin')").run("TXG-"+crypto.randomBytes(6).toString("hex").toUpperCase(),u,e,p,hashPassword(pw)).lastInsertRowid;for(const x of ["dashboard","users","deposits","withdrawals","transactions","settings"])db.prepare("INSERT INTO admin_permissions(admin_id,permission) VALUES(?,?)").run(id,x);audit(req.user.id,"admin_created","user",id,{},req);res.json({ok:true,id})}catch(e){res.status(400).json({error:e.message})}});
app.post("/api/owner/admins/:id/status",auth,roles("owner"),(req,res)=>{const status=req.body.status==="suspended"?"suspended":"active";db.prepare("UPDATE users SET status=?,updated_at=? WHERE id=? AND role='admin'").run(status,now(),req.params.id);audit(req.user.id,"admin_status_changed","user",req.params.id,{status},req);res.json({ok:true})});
app.get("/api/owner/admins/:id/permissions",auth,roles("owner"),(req,res)=>res.json({permissions:db.prepare("SELECT permission FROM admin_permissions WHERE admin_id=?").all(req.params.id).map(x=>x.permission)}));
app.post("/api/owner/admins/:id/permissions",auth,roles("owner"),(req,res)=>{const allowed=["dashboard","users","deposits","withdrawals","transactions","settings"],ps=Array.isArray(req.body.permissions)?req.body.permissions.filter(x=>allowed.includes(x)):[];db.transaction(()=>{db.prepare("DELETE FROM admin_permissions WHERE admin_id=?").run(req.params.id);for(const p of ps)db.prepare("INSERT INTO admin_permissions(admin_id,permission) VALUES(?,?)").run(req.params.id,p)})();audit(req.user.id,"admin_permissions_updated","user",req.params.id,{permissions:ps},req);res.json({ok:true,permissions:ps})});

app.post("/api/admin/users/:id/balance",auth,roles("owner"),(req,res)=>{try{const amount=Number(req.body.amount),reason=String(req.body.reason||"").trim().slice(0,200);if(!Number.isFinite(amount)||amount===0||!reason||Math.abs(amount)>100000000)throw Error("Invalid adjustment.");db.transaction(()=>{const u=db.prepare("SELECT balance FROM users WHERE id=?").get(req.params.id);if(!u)throw Error("User not found.");const nb=Math.round((u.balance+amount)*100)/100;if(nb<0)throw Error("Balance cannot be negative.");db.prepare("UPDATE users SET balance=?,updated_at=? WHERE id=?").run(nb,now(),req.params.id);db.prepare("INSERT INTO ledger(user_id,type,amount,balance_after,reference,description) VALUES(?,?,?,?,?,?)").run(req.params.id,amount>0?"owner_credit":"owner_debit",amount,nb,"ADJ-"+crypto.randomBytes(8).toString("hex"),reason)})();audit(req.user.id,"balance_adjustment","user",req.params.id,{amount,reason},req);res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});

app.get("/api/admin/audit",auth,roles("admin","owner"),(req,res)=>res.json({logs:db.prepare("SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT 1000").all()}));

// Telegram polling: registration OTP does NOT exist until /start is received.
let offset=0;
async function telegramPoll(){
 if(!process.env.TELEGRAM_BOT_TOKEN)return;
 try{
  const r=await axios.get(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getUpdates`,{params:{timeout:20,offset},timeout:25000});
  for(const up of r.data.result||[]){
   offset=up.update_id+1;const m=up.message;if(!m?.chat)continue;const text=String(m.text||"");
   if(text.startsWith("/start")){
    const payload=text.split(/\s+/)[1];
    if(payload){
     const c=db.prepare("SELECT * FROM otp_challenges WHERE token=? AND purpose='register' AND verified_at IS NULL").get(payload);
     if(c&&new Date(c.expires_at)>new Date()){
      const existing=db.prepare("SELECT id FROM users WHERE telegram_chat_id=? AND id<>?").get(String(m.chat.id),c.user_id);
      if(existing){await tgSend(m.chat.id,"This Telegram account is already linked to another TXG account.");continue}
      db.prepare("UPDATE otp_challenges SET started_at=?,telegram_chat_id=? WHERE id=?").run(now(),String(m.chat.id),c.id);
      db.prepare("UPDATE users SET telegram_chat_id=?,telegram_user_id=?,telegram_username=?,telegram_verified=0,updated_at=? WHERE id=?").run(String(m.chat.id),String(m.from?.id||""),uname(m.from?.username||""),now(),c.user_id);
      // Generate/replace OTP only after Start.
      const code=otp();db.prepare("UPDATE otp_challenges SET otp_hash=? WHERE id=?").run(sha(code),c.id);
      await tgSend(m.chat.id,`<b>TXG Gateway verification</b>\n\nYour OTP is <code>${code}</code>\n\nEnter it on the website. It expires in ${Math.ceil(OTP_TTL/60)} minutes.`);
     }else await tgSend(m.chat.id,"Verification link expired. Return to the website and register again.");
    }else await tgSend(m.chat.id,"Welcome to TXG Gateway. Use the Start button from the website to link your account.");
   } else if(text==="/id"){
    await tgSend(m.chat.id,`Telegram User ID: <code>${m.from?.id||"unknown"}</code>`);
   } else if(text==="/help"){
    await tgSend(m.chat.id,"TXG Gateway bot is used for secure account verification and login OTP.");
   }
  }
 }catch(e){if(e.response?.status===409)console.error("Telegram: another getUpdates instance is running.");else console.error("Telegram poll:",e.message)}
}
if(process.env.TELEGRAM_BOT_TOKEN)setInterval(telegramPoll,Number(process.env.TELEGRAM_POLL_SECONDS||1)*1000);

app.listen(Number(process.env.PORT||3000),()=>console.log("TXG Gateway v2 running on port "+(process.env.PORT||3000)));
