const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const url = require('url');

// ── 설정 ──────────────────────────────────────────────────────
const SOLAPI_API_KEY    = process.env.SOLAPI_API_KEY    || 'NCSA4ZHXTUWW3UAW';
const SOLAPI_API_SECRET = process.env.SOLAPI_API_SECRET || 'ZPYPYE5MZAUH6V2AT9UVYOSDLD2HV9SA';
const KAKAO_PF_ID       = process.env.KAKAO_PF_ID       || 'KA01PF240125051006912B6bMzhuVdF6';
const KAKAO_TEMPLATE_ID = process.env.KAKAO_TEMPLATE_ID || '';
const FROM_NUMBER       = process.env.FROM_NUMBER       || '0256744123';
const BUBBLE_API_KEY    = process.env.BUBBLE_API_KEY    || 'a26d3da7ea51af107825ba8d12869714';
const BUBBLE_APP_HOST   = process.env.BUBBLE_APP_HOST   || 'nextleveltransform.com';
const BUBBLE_TYPE       = process.env.BUBBLE_TYPE       || 'nlt버그제안사항';

const DB = {
  host: process.env.DB_HOST || 'bubble-db.c3qewqwk0mog.ap-northeast-2.rds.amazonaws.com',
  port: 3306,
  user: process.env.DB_USER || 'admin',
  password: process.env.DB_PASSWORD || 'theway4123',
  database: process.env.DB_NAME || 'bubble_db',
};

// ── MySQL client ──────────────────────────────────────────────
function sha1(d){return crypto.createHash('sha1').update(d).digest();}
function sha256(d){return crypto.createHash('sha256').update(d).digest();}
function nativePassword(pw,sc){const s1=sha1(Buffer.from(pw)),s2=sha1(s1),s3=sha1(Buffer.concat([sc,s2]));return Buffer.from(s3.map((b,i)=>b^s1[i]));}
function sha2Password(pw,sc){const h1=sha256(Buffer.from(pw)),h2=sha256(h1),h3=sha256(Buffer.concat([h2,sc]));return Buffer.from(h1.map((b,i)=>b^h3[i]));}
function makePacket(payload,seq){const h=Buffer.alloc(4);h[0]=payload.length&0xFF;h[1]=(payload.length>>8)&0xFF;h[2]=(payload.length>>16)&0xFF;h[3]=seq;return Buffer.concat([h,payload]);}
function readLenEnc(buf,off){const f=buf[off];if(f<251)return{value:f,len:1};if(f===251)return{value:null,len:1};if(f===252)return{value:buf.readUInt16LE(off+1),len:3};if(f===253)return{value:buf.readUInt32LE(off+1)&0xFFFFFF,len:4};return{value:Number(buf.readBigUInt64LE(off+1)),len:9};}
function parseResultSet(data){const pkts=[];let pos=0;while(pos+4<=data.length){const len=data[pos]|(data[pos+1]<<8)|(data[pos+2]<<16);pos+=4;if(pos+len>data.length)break;pkts.push(data.slice(pos,pos+len));pos+=len;}if(!pkts.length)return[];const fb=pkts[0][0];if(fb===0xFF)throw new Error(pkts[0].slice(9).toString());if(fb===0x00)return[];let pi=1;const fields=[];while(pi<pkts.length&&pkts[pi][0]!==0xFE){const p=pkts[pi++];let off=0;function skipLS(){const r=readLenEnc(p,off);off+=r.len+r.value;}skipLS();skipLS();skipLS();skipLS();const nr=readLenEnc(p,off);off+=nr.len;fields.push(p.slice(off,off+nr.value).toString());off+=nr.value;}pi++;const rows=[];while(pi<pkts.length&&pkts[pi][0]!==0xFE){const p=pkts[pi++];let off=0;const row={};for(const f of fields){const r=readLenEnc(p,off);off+=r.len;row[f]=r.value===null?null:p.slice(off,off+r.value).toString();if(r.value!==null)off+=r.value;}rows.push(row);}return rows;}

let conn=null,queryQueue=[],connBuf=Buffer.alloc(0),connSeq=0,connState='disconnected';
let currentResolve=null,currentReject=null,currentResultBuf=Buffer.alloc(0);

function connect(){return new Promise((resolve,reject)=>{const sock=new net.Socket();connState='handshake';conn=sock;const timer=setTimeout(()=>{sock.destroy();reject(new Error('DB timeout'));},10000);sock.connect(DB.port,DB.host);sock.on('data',chunk=>{connBuf=Buffer.concat([connBuf,chunk]);pumpConn(resolve,reject);});sock.on('error',err=>{clearTimeout(timer);connState='disconnected';conn=null;(currentReject||reject)(err);});sock.on('close',()=>{connState='disconnected';conn=null;});const orig=resolve;resolve=(...a)=>{clearTimeout(timer);orig(...a);}});}
function getNextConnPkt(){if(connBuf.length<4)return null;const len=connBuf[0]|(connBuf[1]<<8)|(connBuf[2]<<16);if(connBuf.length<len+4)return null;connSeq=connBuf[3]+1;const p=connBuf.slice(4,4+len);connBuf=connBuf.slice(4+len);return p;}
function pumpConn(r,j){let pkt;while((pkt=getNextConnPkt())!==null)handleConnPkt(pkt,r,j);}
function handleConnPkt(pkt,connResolve,connReject){if(connState==='handshake'){const nul=pkt.indexOf(0,1);let pos=nul+1+4;const sc1=pkt.slice(pos,pos+8);pos+=8+1+2+1+2+2+1+10;const sc2=pkt.slice(pos,pos+12);pos+=13;const scramble=Buffer.concat([sc1,sc2]);const plugEnd=pkt.indexOf(0,pos);const plugin=pkt.slice(pos,plugEnd).toString();const hash=plugin==='caching_sha2_password'?sha2Password(DB.password,scramble):nativePassword(DB.password,scramble);const user=Buffer.from(DB.user+'\0'),db=Buffer.from(DB.database+'\0'),plug=Buffer.from(plugin+'\0');conn.write(makePacket(Buffer.concat([Buffer.from([0x8D,0xA2,0x0F,0x00]),Buffer.from([0x00,0x00,0x00,0x01]),Buffer.from([0x21]),Buffer.alloc(23),user,Buffer.from([hash.length]),hash,db,plug]),connSeq++));connState='auth';}else if(connState==='auth'){if(pkt[0]===0x00){connState='idle';if(connResolve)connResolve();processQueue();}else if(pkt[0]===0xFF){connState='disconnected';(connReject||currentReject)(new Error(pkt.slice(9).toString()));}else if(pkt[0]===0xFE){const nul=pkt.indexOf(0,1);const pl=pkt.slice(1,nul).toString();const d=pkt.slice(nul+1,nul+21);const h=pl==='caching_sha2_password'?sha2Password(DB.password,d):nativePassword(DB.password,d);conn.write(makePacket(h,connSeq++));}else if(pkt[0]===0x01&&pkt[1]===0x04){conn.write(makePacket(Buffer.concat([Buffer.from(DB.password),Buffer.from([0])]),connSeq++));}}else if(connState==='querying'){const h=Buffer.alloc(4);h[0]=pkt.length&0xFF;h[1]=(pkt.length>>8)&0xFF;h[2]=(pkt.length>>16)&0xFF;currentResultBuf=Buffer.concat([currentResultBuf,h,pkt]);let done=false;if(pkt[0]===0x00){done=true;}else if(pkt[0]===0xFE&&pkt.length<9){let eof=0,p=0;while(p+4<=currentResultBuf.length){const l=currentResultBuf[p]|(currentResultBuf[p+1]<<8)|(currentResultBuf[p+2]<<16);const pl=currentResultBuf.slice(p+4,p+4+l);if(pl[0]===0xFE&&l<9)eof++;p+=4+l;}if(eof>=2)done=true;}else if(pkt[0]===0xFF){done=true;}if(done){connState='idle';const res=currentResolve,rej=currentReject,rbuf=currentResultBuf;currentResolve=null;currentReject=null;currentResultBuf=Buffer.alloc(0);try{res(parseResultSet(rbuf));}catch(e){rej(e);}processQueue();}}}
function processQueue(){if(connState!=='idle'||queryQueue.length===0)return;const{sql,resolve,reject}=queryQueue.shift();currentResolve=resolve;currentReject=reject;currentResultBuf=Buffer.alloc(0);connState='querying';const q=Buffer.from(sql);const p=Buffer.alloc(q.length+1);p[0]=0x03;q.copy(p,1);conn.write(makePacket(p,0));connSeq=1;}
function query(sql){return new Promise((resolve,reject)=>{queryQueue.push({sql,resolve,reject});if(connState==='idle')processQueue();});}
function esc(v){return (v||'').replace(/'/g,"''");}

// ── Solapi 알림톡 ─────────────────────────────────────────────
function getSolapiAuth(){const date=new Date().toISOString();const salt=crypto.randomBytes(8).toString('hex');const sig=crypto.createHmac('sha256',SOLAPI_API_SECRET).update(SOLAPI_API_KEY+date+salt).digest('hex');return `HMAC-SHA256 apiKey=${SOLAPI_API_KEY}, date=${date}, salt=${salt}, signature=${sig}`;}

function sendKakao(phone,name,inquiryType,content,answer){return new Promise((resolve)=>{if(!KAKAO_TEMPLATE_ID){resolve({skipped:true,reason:'템플릿 ID 미설정'});return;}const cleanPhone=phone.replace(/[^0-9]/g,'');const body=JSON.stringify({message:{to:cleanPhone,from:FROM_NUMBER,kakaoOptions:{pfId:KAKAO_PF_ID,templateId:KAKAO_TEMPLATE_ID,variables:{'#{고객명}':name||'고객','#{문의유형}':inquiryType||'문의','#{문의내용}':content.length>80?content.slice(0,80)+'...':content,'#{답변내용}':answer}}}});const req=https.request({hostname:'api.solapi.com',path:'/messages/v4/send',method:'POST',headers:{'Content-Type':'application/json','Authorization':getSolapiAuth(),'Content-Length':Buffer.byteLength(body)}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(JSON.parse(d));}catch{resolve({raw:d});}});});req.on('error',e=>resolve({error:e.message}));req.write(body);req.end();});}

// ── Bubble API 업데이트 ───────────────────────────────────────
function updateBubble(bugId,answer){return new Promise((resolve)=>{const body=JSON.stringify({'답변 여부':true,'답변하기':answer});const path=`/api/1.1/obj/${encodeURIComponent(BUBBLE_TYPE)}/${bugId}`;const req=https.request({hostname:BUBBLE_APP_HOST,path,method:'PATCH',headers:{'Content-Type':'application/json','Authorization':`Bearer ${BUBBLE_API_KEY}`,'Content-Length':Buffer.byteLength(body)}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve({status:res.statusCode,body:JSON.parse(d)});}catch{resolve({status:res.statusCode,raw:d});}});});req.on('error',e=>resolve({error:e.message}));req.write(body);req.end();});}

// ── Bubble API GET (미디어/전체 필드) ─────────────────────────
function getBubbleRecord(bugId){return new Promise((resolve)=>{const path=`/api/1.1/obj/${encodeURIComponent(BUBBLE_TYPE)}/${bugId}`;const req=https.request({hostname:BUBBLE_APP_HOST,path,method:'GET',headers:{'Authorization':`Bearer ${BUBBLE_API_KEY}`}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(JSON.parse(d));}catch{resolve(null);}});});req.on('error',()=>resolve(null));req.end();});}

// ── Bubble → MySQL 동기화 ─────────────────────────────────────
async function syncFromBubble(){
  try {
    // Bubble에서 답변완료 레코드 가져오기
    const path=`/api/1.1/obj/${encodeURIComponent(BUBBLE_TYPE)}?constraints=${encodeURIComponent(JSON.stringify([{key:'답변 여부',constraint_type:'equals',value:true}]))}&limit=100`;
    const data = await new Promise((resolve)=>{const req=https.request({hostname:BUBBLE_APP_HOST,path,method:'GET',headers:{'Authorization':`Bearer ${BUBBLE_API_KEY}`}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>{try{resolve(JSON.parse(d));}catch{resolve(null);}});});req.on('error',()=>resolve(null));req.end();});
    if(!data||!data.response||!data.response.results) return {synced:0};
    const records = data.response.results;
    let synced=0;
    for(const r of records){
      if(!r._id||!r['답변하기']) continue;
      const esc_id=r._id.replace(/'/g,"''");
      const esc_ans=(r['답변하기']||'').replace(/'/g,"''");
      const existing=await query(`SELECT answered FROM bug_report_sync WHERE bug_id='${esc_id}' LIMIT 1`);
      if(existing.length && existing[0].answered==='0'){
        await query(`UPDATE bug_report_sync SET answered=1, answer='${esc_ans}', updated_at=NOW() WHERE bug_id='${esc_id}'`);
        synced++;
      }
    }
    return {synced, total:records.length};
  } catch(e){ return {error:e.message}; }
}

// ── Slack 알림 ────────────────────────────────────────────────
const SLACK_WEBHOOK = process.env.SLACK_WEBHOOK || '';
let lastCheckedAt = new Date().toISOString().slice(0,19).replace('T',' ');

function getFirstSentence(text){
  if(!text) return '내용 없음';
  const cleaned=String(text).trim();
  const match=cleaned.match(/[^.!?。！？\n]+[.!?。！？]?/);
  return match?match[0].trim():cleaned.slice(0,80);
}

function sendSlack(bug){
  if(!SLACK_WEBHOOK) return;
  try {
    const u=new URL(SLACK_WEBHOOK);
    const summary=getFirstSentence(bug.content);
    const product=bug.product_name||'미분류';
    const body=JSON.stringify({
      text:`🍩 신규 버그가 등록되었습니다! 제품 : ${product} | 내용 요약 : '${summary}'`,
      blocks:[
        {type:'section',text:{type:'mrkdwn',text:`🍩 *신규 버그가 등록되었습니다!*\n제품 : *${product}*\n내용 요약 : '${summary}'`}},
        {type:'actions',elements:[{type:'button',text:{type:'plain_text',text:'버그 해결하러 가기',emoji:true},url:'https://bugdesk.vercel.app',style:'primary'}]}
      ]
    });
    const req=https.request({hostname:u.hostname,path:u.pathname+u.search,method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},()=>{});
    req.on('error',()=>{});
    req.write(body); req.end();
  } catch(e){}
}

async function initSlackColumn(){
  try {
    await query(`ALTER TABLE bug_report_sync ADD COLUMN IF NOT EXISTS slack_notified TINYINT DEFAULT 0`);
  } catch(e){}
}

// ── 미답변 리마인더 (수/금 오전 10시 KST) ─────────────────────
let lastReminderDate = '';

async function checkUnansweredReminder(){
  try {
    const kst = new Date(Date.now() + 9 * 60 * 60 * 1000);
    const day  = kst.getUTCDay();   // 3=수, 5=금
    const hour = kst.getUTCHours(); // 10시
    const dateStr = kst.toISOString().slice(0, 10);
    if ((day === 3 || day === 5) && hour === 10 && dateStr !== lastReminderDate) {
      lastReminderDate = dateStr;
      const rows = await query(`SELECT COUNT(*) AS cnt FROM bug_report_sync WHERE answered=0 AND created_at >= '2026-06-01' AND created_at <= NOW() - INTERVAL 48 HOUR`);
      const cnt = Number(rows[0].cnt);
      if (cnt > 0) sendSlackReminder(cnt);
    }
  } catch(e){}
}

function sendSlackReminder(cnt){
  if(!SLACK_WEBHOOK) return;
  try {
    const u = new URL(SLACK_WEBHOOK);
    const body = JSON.stringify({
      text: `❤️‍🔥 현재 2일 넘게 응답되지 않은 답변이 ${cnt}건 있습니다.\n고객이 기다리지 않게 서둘러 답변해주세요 !`,
      blocks: [
        {type:'section', text:{type:'mrkdwn', text:`❤️‍🔥 현재 2일 넘게 응답되지 않은 답변이 *${cnt}건* 있습니다.\n고객이 기다리지 않게 서둘러 답변해주세요 !`}},
        {type:'actions', elements:[{type:'button', text:{type:'plain_text', text:'버그 해결하러 가기', emoji:true}, url:'https://bugdesk.vercel.app', style:'primary'}]}
      ]
    });
    const req = https.request({hostname:u.hostname, path:u.pathname+u.search, method:'POST', headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}}, ()=>{});
    req.on('error', ()=>{});
    req.write(body); req.end();
  } catch(e){}
}

async function pollNewBugs(){
  try {
    const rows=await query(`SELECT bug_id, product_name, type, email, content, created_at FROM bug_report_sync WHERE (slack_notified IS NULL OR slack_notified=0) ORDER BY created_at ASC LIMIT 20`);
    for(const r of rows){
      sendSlack(r);
      await query(`UPDATE bug_report_sync SET slack_notified=1 WHERE bug_id='${esc(r.bug_id)}'`);
    }
  } catch(e){}
}

// ── 키워드 빈도 분석 ──────────────────────────────────────────
const STOP_WORDS=new Set(['이','가','을','를','은','는','에','에서','으로','로','와','과','의','도','만','것','수','그','저','제','안녕하세요','감사합니다','안녕','네','아','그런데','그리고','하지만','또한','그래서','때문에','같은','같이','때','중','후','전','부터','까지','위해','위한','통해','통한','대해','대한','이용','사용','합니다','입니다','습니다','니다','세요','주세요','해주세요','해요','아요','어요','있어요','없어요','있습니다','없습니다','있는데','있는','없는','하는','되는','됩니다','하고','이고','이며','이나','이랑','있고','없고','하면','되면','이면','있으면','없으면','같아요','같습니다','같은데','감사','부탁','드립니다','드려요','주시면','주시기','바랍니다','부탁드립니다','확인','관련','관한','내용','문의','사항']);
function extractKeywords(texts){const freq={};for(const text of texts){const words=text.replace(/[^가-힣a-zA-Z0-9 ]/g,' ').split(/\s+/);for(const w of words){if(w.length<2)continue;if(STOP_WORDS.has(w))continue;const stem=w.replace(/(요|니다|어서|아서|에서|이에요|예요|이요)$/,'');if(stem.length<2)continue;freq[stem]=(freq[stem]||0)+1;}}return Object.entries(freq).sort((a,b)=>b[1]-a[1]).slice(0,15);}

// ── HTML ──────────────────────────────────────────────────────
function buildHTML(){
  const kakaoReady=KAKAO_TEMPLATE_ID?'연결됨':'템플릿 미설정';
  const kakaoColor=KAKAO_TEMPLATE_ID?'#34d399':'#fbbf24';
  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>문의 관리 대시보드</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;padding:28px 24px;}
h1{font-size:20px;font-weight:700;color:#f8fafc;margin-bottom:4px;}
.sub{font-size:12px;color:#475569;margin-bottom:16px;}
.kakao-badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600;background:#1e2130;color:${kakaoColor};border:1px solid ${kakaoColor}33;margin-left:10px;vertical-align:middle;}
.tab-bar{display:flex;gap:0;margin-bottom:24px;border-bottom:2px solid #2d3348;}
.tab-btn{background:none;border:none;border-bottom:3px solid transparent;margin-bottom:-2px;color:#64748b;padding:10px 24px;font-size:14px;font-weight:600;cursor:pointer;}
.tab-btn.active{color:#60a5fa;border-bottom-color:#60a5fa;}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px;}
.stat{background:#1e2130;border:1px solid #2d3348;border-radius:12px;padding:16px 20px;text-align:center;}
.stat .n{font-size:36px;font-weight:800;line-height:1;margin-bottom:4px;}
.stat .l{font-size:12px;color:#94a3b8;}
.stat.total .n{color:#60a5fa;}.stat.unans .n{color:#fb7185;}.stat.ans .n{color:#34d399;}
.filter-bar{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center;}
select,input[type=text],input[type=date]{background:#1e2130;border:1px solid #2d3348;border-radius:8px;color:#e2e8f0;padding:7px 12px;font-size:13px;}
.btn{background:#3b82f6;border:none;color:#fff;padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;}
.btn:hover{background:#2563eb;}
.btn-sm{padding:5px 12px;font-size:12px;border-radius:6px;}
.btn-answer{background:#8b5cf6;}.btn-answer:hover{background:#7c3aed;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:9px 12px;font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:#64748b;border-bottom:1px solid #2d3348;}
td{padding:10px 12px;border-bottom:1px solid #1a1f2e;color:#cbd5e1;vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tr.bug-row:hover td{background:#1a1f2e;cursor:pointer;}
.badge{display:inline-block;padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-unans{background:#4c0519;color:#fb7185;}.badge-ans{background:#064e3b;color:#34d399;}
.preview{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#94a3b8;font-size:12px;}
.detail-row{display:none;}.detail-row.open{display:table-row;}
.detail-cell{padding:16px 20px!important;background:#161b27!important;border-bottom:1px solid #2d3348!important;}
.detail-inner{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
.detail-section{background:#1e2130;border-radius:10px;padding:16px;}
.detail-label{font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#475569;margin-bottom:8px;}
.detail-content{font-size:13px;color:#e2e8f0;line-height:1.7;white-space:pre-wrap;word-break:break-all;}
.answer-area{width:100%;background:#0f1117;border:1px solid #2d3348;border-radius:8px;color:#e2e8f0;padding:10px 12px;font-size:13px;resize:vertical;min-height:100px;font-family:inherit;margin-top:10px;}
.answer-area:focus{outline:none;border-color:#8b5cf6;}
.answer-footer{display:flex;align-items:center;gap:10px;margin-top:10px;}
.kakao-note{font-size:11px;color:#64748b;}
.existing-answer{font-size:13px;color:#a78bfa;line-height:1.7;white-space:pre-wrap;background:#160d2e;border-radius:8px;padding:12px;margin-top:8px;}
.card{background:#1e2130;border:1px solid #2d3348;border-radius:12px;}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px;margin-top:16px;}
.summary-card{background:#1e2130;border:1px solid #2d3348;border-radius:12px;padding:18px 20px;}
.summary-product{font-size:14px;font-weight:700;color:#a78bfa;margin-bottom:8px;}
.summary-count{font-size:28px;font-weight:800;color:#60a5fa;margin-bottom:12px;}
.kw-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;}
.kw-tag{background:#1a1f2e;border:1px solid #2d3348;border-radius:20px;padding:3px 10px;font-size:12px;color:#94a3b8;}
.kw-tag .kw-n{color:#fbbf24;font-weight:700;margin-left:4px;}
.type-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1f2e;font-size:12px;}
.type-row:last-child{border-bottom:none;}
</style>
</head>
<body>
<h1>문의 관리 대시보드 <span class="kakao-badge">카카오 알림톡 ${kakaoReady}</span></h1>
<div class="sub">bug_report_sync 실시간 연동 · Bubble 연동됨</div>

<div class="tab-bar">
  <button class="tab-btn active" id="tab-list" onclick="switchTab('list')">문의 목록</button>
  <button class="tab-btn" id="tab-summary" onclick="switchTab('summary')">제품별 분석</button>
</div>

<!-- 문의 목록 탭 -->
<div id="panel-list">
<div class="stats">
  <div class="stat total"><div class="n" id="statTotal">-</div><div class="l">전체 문의</div></div>
  <div class="stat unans"><div class="n" id="statUnans">-</div><div class="l">미답변</div></div>
  <div class="stat ans"><div class="n" id="statAns">-</div><div class="l">답변 완료</div></div>
</div>
<div class="filter-bar">
  <select id="fProduct" onchange="load()"><option value="">전체 제품</option></select>
  <select id="fType" onchange="load()"><option value="">전체 유형</option></select>
  <select id="fAnswered" onchange="load()">
    <option value="">전체</option>
    <option value="0">미답변</option>
    <option value="1">답변완료</option>
  </select>
  <input type="text" id="fSearch" placeholder="이메일 또는 내용 검색..." style="width:220px" oninput="filterLocal()"/>
  <button class="btn btn-sm" onclick="load(true)">새로고침</button>
  <button class="btn btn-sm" id="syncBtn" onclick="syncBubble()" style="background:#0e7490">Bubble 동기화</button>
</div>
<div class="card">
<table>
  <thead><tr><th>날짜</th><th>제품</th><th>유형</th><th>세부유형</th><th>이메일</th><th>내용 미리보기</th><th>상태</th></tr></thead>
  <tbody id="bugTable"><tr><td colspan="7" style="text-align:center;color:#475569;padding:32px">불러오는 중...</td></tr></tbody>
</table>
</div>
</div><!-- /panel-list -->

<!-- 제품별 분석 탭 -->
<div id="panel-summary" style="display:none">
<div class="filter-bar">
  <label style="font-size:12px;color:#64748b">시작일</label>
  <input type="date" id="sStart"/>
  <label style="font-size:12px;color:#64748b">종료일</label>
  <input type="date" id="sEnd"/>
  <button class="btn btn-sm" onclick="loadSummary()">조회</button>
  <span id="sTotal" style="font-size:12px;color:#64748b"></span>
</div>
<div id="summaryGrid" class="summary-grid"></div>
</div>

<script>
let allBugs=[], openIdx=null, openBugId=null, mediaCache={};

function switchTab(tab){
  document.getElementById('panel-list').style.display=tab==='list'?'':'none';
  document.getElementById('panel-summary').style.display=tab==='summary'?'':'none';
  document.getElementById('tab-list').classList.toggle('active',tab==='list');
  document.getElementById('tab-summary').classList.toggle('active',tab==='summary');
  if(tab==='summary'&&!document.getElementById('summaryGrid').innerHTML) loadSummary();
}

async function load(manual=false){
  // 자동 새로고침 시: 작성 중인 내용 있으면 건너뜀
  if(!manual){
    const areas=document.querySelectorAll('.answer-area');
    for(const a of areas){ if(a.value.trim()) return; }
  }
  const product=document.getElementById('fProduct').value;
  const type=document.getElementById('fType').value;
  const answered=document.getElementById('fAnswered').value;
  let qs='';
  if(product) qs+='&product='+encodeURIComponent(product);
  if(type) qs+='&type='+encodeURIComponent(type);
  if(answered!=='') qs+='&answered='+answered;
  const res=await fetch('/api/bugs?'+qs.slice(1));
  const data=await res.json();
  allBugs=data.bugs||[];
  const pSel=document.getElementById('fProduct'),curP=pSel.value;
  pSel.innerHTML='<option value="">전체 제품</option>'+(data.products||[]).map(p=>\`<option value="\${p}"\${p===curP?' selected':''}>\${p}</option>\`).join('');
  const tSel=document.getElementById('fType'),curT=tSel.value;
  tSel.innerHTML='<option value="">전체 유형</option>'+(data.types||[]).map(t=>\`<option value="\${t}"\${t===curT?' selected':''}>\${t}</option>\`).join('');
  document.getElementById('statTotal').textContent=data.totalCount||0;
  document.getElementById('statUnans').textContent=data.unansCount||0;
  document.getElementById('statAns').textContent=data.ansCount||0;
  filterLocal();
}

function filterLocal(){
  const q=document.getElementById('fSearch').value.toLowerCase();
  const filtered=q?allBugs.filter(b=>(b.email||'').toLowerCase().includes(q)||(b.content||'').toLowerCase().includes(q)):allBugs;
  renderTable(filtered);
}

function renderTable(bugs){
  const tbody=document.getElementById('bugTable');
  if(!bugs.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:#475569;padding:32px">문의 내역이 없습니다.</td></tr>';return;}
  tbody.innerHTML='';
  bugs.forEach((b,i)=>{
    const isOpen = b.bug_id === openBugId;
    const isAns=b.answered==='1'||b.answered===1;
    const dt=(b.created_at||'').slice(0,16);
    tbody.innerHTML+=\`
    <tr class="bug-row" onclick="toggleDetail(\${i})">
      <td style="font-size:12px;color:#64748b;white-space:nowrap">\${dt}</td>
      <td style="font-size:12px;font-weight:600;color:#a78bfa">\${b.product_name||'-'}</td>
      <td style="font-size:12px">\${b.type||'-'}</td>
      <td style="font-size:12px;color:#64748b">\${b.subtype||'-'}</td>
      <td style="font-size:12px;color:#94a3b8">\${b.email||'-'}</td>
      <td><div class="preview">\${b.content||''}</div></td>
      <td><span class="badge \${isAns?'badge-ans':'badge-unans'}">\${isAns?'답변완료':'미답변'}</span></td>
    </tr>
    <tr class="detail-row\${isOpen?' open':''}" id="detail-\${i}">
      <td class="detail-cell" colspan="7">
        <div class="detail-inner">
          <div>
            <div class="detail-section">
              <div class="detail-label">문의 내용</div>
              <div class="detail-content">\${(b.content||'').replace(/</g,'&lt;')}</div>
            </div>
            <div class="detail-section" style="margin-top:12px">
              <div class="detail-label">첨부 미디어</div>
              <div id="media-\${i}" style="margin-top:6px"><span style="color:#334155;font-size:12px">불러오는 중...</span></div>
            </div>
            \${isAns&&b.answer?\`<div class="detail-section" style="margin-top:12px"><div class="detail-label" style="color:#8b5cf6">기존 답변</div><div class="existing-answer">\${(b.answer||'').replace(/</g,'&lt;')}</div></div>\`:''}
          </div>
          <div class="detail-section">
            <div class="detail-label">답변 작성</div>
            <div style="font-size:12px;color:#64748b;margin-bottom:6px">\${b.email||'이메일 없음'} · \${b.product_name||''}</div>
            <textarea class="answer-area" id="ans-\${i}" placeholder="답변 내용을 입력하세요...">\${isAns&&b.answer?b.answer:''}</textarea>
            <div class="answer-footer">
              <button class="btn btn-answer btn-sm" onclick="submitAnswer('\${b.bug_id}',\${i})">\${isAns?'답변 수정':'답변 전송'}</button>
              <span class="kakao-note">${KAKAO_TEMPLATE_ID?'📲 알림톡 자동 발송':'⚠ 알림톡 템플릿 미설정'}</span>
            </div>
            <div id="result-\${i}" style="margin-top:8px;font-size:12px;"></div>
          </div>
        </div>
      </td>
    </tr>\`;
  });
  // 열려있던 행 미디어 캐시 복원
  if(openBugId){
    const oi=bugs.findIndex(b=>b.bug_id===openBugId);
    if(oi>=0){
      const el=document.getElementById('media-'+oi);
      if(el&&mediaCache[openBugId]!==undefined) el.innerHTML=mediaCache[openBugId];
      else if(el&&mediaCache[openBugId]===undefined) loadMedia(openBugId,el);
    }
  }
}

function fixUrl(u){if(!u)return '';return u.startsWith('//')?'https:'+u:u;}
function mediaTag(rawUrl){
  const u=fixUrl(rawUrl);
  if(!u) return '';
  const ext=u.split('?')[0].split('.').pop().toLowerCase();
  if(['jpg','jpeg','png','gif','webp','heic','bmp'].includes(ext)){
    return \`<img src="\${u}" style="max-width:100%;border-radius:8px;margin-bottom:8px;display:block" onerror="this.style.display='none'"/>\`;
  }
  return \`<video controls style="max-width:100%;border-radius:8px;margin-bottom:8px;display:block"><source src="\${u}">영상을 재생할 수 없습니다.</video>\`;
}

async function loadMedia(bugId, mediaEl){
  if(mediaCache[bugId]!==undefined){mediaEl.innerHTML=mediaCache[bugId];return;}
  mediaEl.innerHTML='<span style="color:#475569;font-size:12px">불러오는 중...</span>';
  const data=await fetch('/api/bubble-record/'+bugId).then(r=>r.json()).catch(()=>null);
  let html='';
  if(data&&data.response){
    const r=data.response;
    const rawUrl=r['url']||'';
    if(rawUrl&&rawUrl!=='https://'&&rawUrl.length>8) html+=\`<a href="\${rawUrl}" target="_blank" style="color:#60a5fa;font-size:12px;display:block;margin-bottom:6px">🔗 \${rawUrl}</a>\`;
    ['첨부이미지'].forEach(k=>{
      if(r[k]){const arr=Array.isArray(r[k])?r[k]:[r[k]];arr.forEach(u=>{html+=mediaTag(u);});}
    });
    ['video_file','video'].forEach(k=>{if(r[k]) html+=mediaTag(r[k]);});
  }
  mediaCache[bugId]=html||'<span style="color:#334155;font-size:12px">첨부파일 없음</span>';
  mediaEl.innerHTML=mediaCache[bugId];
}

async function toggleDetail(i){
  const row=document.getElementById('detail-'+i);
  if(openIdx!==null&&openIdx!==i){const prev=document.getElementById('detail-'+openIdx);if(prev)prev.classList.remove('open');}
  row.classList.toggle('open');
  openIdx=row.classList.contains('open')?i:null;
  openBugId=row.classList.contains('open')?(allBugs[i]?.bug_id||null):null;
  if(row.classList.contains('open')){
    const bugId=allBugs[i].bug_id;
    const mediaEl=document.getElementById('media-'+i);
    if(mediaEl) await loadMedia(bugId,mediaEl);
  }
}

async function syncBubble(){
  const btn=document.getElementById('syncBtn');
  btn.disabled=true; btn.textContent='동기화 중...';
  const res=await fetch('/api/sync-bubble',{method:'POST'});
  const d=await res.json();
  btn.disabled=false; btn.textContent='Bubble 동기화';
  alert(d.error?'오류: '+d.error:\`동기화 완료: \${d.synced}건 업데이트 (전체 답변 \${d.total}건)\`);
  load();
}

async function submitAnswer(bugId,i){
  const answer=document.getElementById('ans-'+i).value.trim();
  if(!answer){alert('답변 내용을 입력해주세요.');return;}
  const btn=event.target;
  btn.disabled=true;btn.textContent='전송 중...';
  const resultEl=document.getElementById('result-'+i);
  try{
    const res=await fetch('/api/bugs/'+bugId+'/answer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({answer})});
    const data=await res.json();
    if(data.success){
      let msg='✅ MySQL 저장됨.';
      if(data.bubble&&data.bubble.status===200) msg+=' 🔵 Bubble 반영됨.';
      else if(data.bubble&&data.bubble.error) msg+=' ⚠ Bubble 오류';
      else if(data.bubble) msg+=\` (Bubble: \${data.bubble.status})\`;
      if(data.kakao&&!data.kakao.skipped) msg+=data.kakao.errorCode?' ⚠ 알림톡 실패':' 📲 알림톡 발송됨';
      resultEl.style.color='#34d399';resultEl.textContent=msg;
      load(true);
    }else{resultEl.style.color='#fb7185';resultEl.textContent='❌ '+(data.error||'오류 발생');}
  }catch(e){resultEl.style.color='#fb7185';resultEl.textContent='❌ 네트워크 오류';}
  btn.disabled=false;btn.textContent='답변 전송';
}

async function loadSummary(){
  const start=document.getElementById('sStart').value;
  const end=document.getElementById('sEnd').value;
  let qs='';
  if(start) qs+='&start='+start;
  if(end) qs+='&end='+end;
  document.getElementById('summaryGrid').innerHTML='<div style="color:#475569;font-size:13px;padding:20px">분석 중...</div>';
  const res=await fetch('/api/summary?'+qs.slice(1));
  const data=await res.json();
  document.getElementById('sTotal').textContent=\`전체 \${data.total}건\`;
  const grid=document.getElementById('summaryGrid');
  grid.innerHTML='';
  (data.summary||[]).forEach(p=>{
    const typeRows=p.types.slice(0,5).map(([t,n])=>\`<div class="type-row"><span style="color:#94a3b8">\${t}</span><span style="color:#60a5fa;font-weight:700">\${n}건</span></div>\`).join('');
    const kwTags=p.keywords.map(([w,n])=>\`<span class="kw-tag">\${w}<span class="kw-n">\${n}</span></span>\`).join('');
    grid.innerHTML+=\`<div class="summary-card">
      <div class="summary-product">\${p.product}</div>
      <div class="summary-count">\${p.total}<span style="font-size:14px;color:#64748b;font-weight:400">건</span></div>
      <div style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#475569;margin-bottom:8px">문의 유형</div>
      \${typeRows}
      <div style="font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#475569;margin:12px 0 8px">주요 키워드</div>
      <div class="kw-list">\${kwTags||'<span style="color:#334155;font-size:12px">키워드 없음</span>'}</div>
    </div>\`;
  });
  if(!data.summary||!data.summary.length) grid.innerHTML='<div style="color:#475569;font-size:13px;padding:20px">해당 기간 데이터 없음</div>';
}

load();
setInterval(load, 30000);
</script>
</body>
</html>`;
}

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const getBody = () => new Promise(resolve => { let d=''; req.on('data',c=>d+=c); req.on('end',()=>{try{resolve(JSON.parse(d));}catch{resolve({});}}); });

  if (parsed.pathname.startsWith('/api/bubble-record/') && req.method === 'GET') {
    const bugId = parsed.pathname.split('/')[3];
    const data = await getBubbleRecord(bugId);
    res.writeHead(200,{'Content-Type':'application/json;charset=utf-8'});
    res.end(JSON.stringify(data));

  } else if (parsed.pathname === '/api/sync-bubble' && req.method === 'POST') {
    const result = await syncFromBubble();
    res.writeHead(200,{'Content-Type':'application/json;charset=utf-8'});
    res.end(JSON.stringify(result));

  } else if (parsed.pathname === '/api/bugs' && req.method === 'GET') {
    const product=parsed.query.product||'', type=parsed.query.type||'', answered=parsed.query.answered;
    let where='1=1';
    if(product) where+=` AND product_name='${esc(product)}'`;
    if(type) where+=` AND type='${esc(type)}'`;
    if(answered!==undefined&&answered!=='') where+=` AND answered=${answered==='1'?1:0}`;
    try {
      const bugs     = await query(`SELECT * FROM bug_report_sync WHERE ${where} ORDER BY created_at DESC LIMIT 300`);
      const stats    = await query(`SELECT COUNT(*) AS total, SUM(answered=0) AS unans, SUM(answered=1) AS ans FROM bug_report_sync`);
      const products = await query(`SELECT DISTINCT product_name FROM bug_report_sync WHERE product_name IS NOT NULL AND product_name!='' ORDER BY product_name`);
      const types    = await query(`SELECT DISTINCT type FROM bug_report_sync WHERE type IS NOT NULL AND type!='' ORDER BY type`);
      res.writeHead(200,{'Content-Type':'application/json;charset=utf-8'});
      res.end(JSON.stringify({bugs,totalCount:Number(stats[0].total),unansCount:Number(stats[0].unans),ansCount:Number(stats[0].ans),products:products.map(p=>p.product_name),types:types.map(t=>t.type)}));
    } catch(e){res.writeHead(500);res.end(JSON.stringify({error:e.message}));}

  } else if (req.method==='POST' && parsed.pathname.startsWith('/api/bugs/') && parsed.pathname.endsWith('/answer')) {
    const bugId = parsed.pathname.split('/')[3];
    const {answer} = await getBody();
    if(!answer||!answer.trim()){res.writeHead(400);res.end(JSON.stringify({error:'답변을 입력해주세요'}));return;}
    try {
      const bugs = await query(`SELECT * FROM bug_report_sync WHERE bug_id='${esc(bugId)}' LIMIT 1`);
      if(!bugs.length){res.writeHead(404);res.end(JSON.stringify({error:'문의를 찾을 수 없어요'}));return;}
      const bug = bugs[0];
      await query(`UPDATE bug_report_sync SET answered=1, answer='${esc(answer)}', updated_at=NOW() WHERE bug_id='${esc(bugId)}'`);
      let kakaoResult={skipped:true,reason:'전화번호 없음'};
      const phones = await query(`SELECT phone FROM payments_sync WHERE uniqueid='${esc(bug.uniqueid)}' AND phone IS NOT NULL AND phone!='' LIMIT 1`);
      if(phones.length) kakaoResult=await sendKakao(phones[0].phone,bug.email||'고객',bug.type||'문의',bug.content||'',answer);
      const bubbleResult = await updateBubble(bugId, answer);
      res.writeHead(200,{'Content-Type':'application/json;charset=utf-8'});
      res.end(JSON.stringify({success:true,kakao:kakaoResult,bubble:bubbleResult}));
    } catch(e){res.writeHead(500);res.end(JSON.stringify({error:e.message}));}

  } else if (parsed.pathname === '/api/summary' && req.method === 'GET') {
    const start=parsed.query.start||'', end=parsed.query.end||'';
    let where='1=1';
    if(start) where+=` AND DATE(created_at) >= '${esc(start)}'`;
    if(end)   where+=` AND DATE(created_at) <= '${esc(end)}'`;
    try {
      const rows = await query(`SELECT product_name, type, subtype, content FROM bug_report_sync WHERE ${where} ORDER BY created_at DESC`);
      const byProduct={};
      for(const r of rows){
        const p=r.product_name||'미분류';
        if(!byProduct[p]) byProduct[p]={total:0,types:{},contents:[]};
        byProduct[p].total++;
        const t=r.type||'기타';
        byProduct[p].types[t]=(byProduct[p].types[t]||0)+1;
        if(r.content) byProduct[p].contents.push(r.content);
      }
      const summary=Object.entries(byProduct).map(([product,data])=>({product,total:data.total,types:Object.entries(data.types).sort((a,b)=>b[1]-a[1]),keywords:extractKeywords(data.contents)})).sort((a,b)=>b.total-a.total);
      res.writeHead(200,{'Content-Type':'application/json;charset=utf-8'});
      res.end(JSON.stringify({summary,total:rows.length}));
    } catch(e){res.writeHead(500);res.end(JSON.stringify({error:e.message}));}

  } else {
    res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'});
    res.end(buildHTML());
  }
});

function startDB(){connect().then(()=>console.log('DB connected')).catch(err=>{console.error('DB failed:',err.message);setTimeout(startDB,3000);});}

function startAll(){
  startDB();
  // DB 준비 후 컬럼 초기화 + 폴링 시작
  setTimeout(async ()=>{
    await initSlackColumn();
    if(SLACK_WEBHOOK) setInterval(pollNewBugs, 60000);
    if(SLACK_WEBHOOK) setInterval(checkUnansweredReminder, 60000);
  }, 3000);
}

if(require.main===module){
  const PORT=process.env.PORT||3001;
  server.listen(PORT,()=>console.log('BugDesk running at http://localhost:'+PORT));
  startAll();
}else{startAll();module.exports=server;}
