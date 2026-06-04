const net = require('net');
const https = require('https');
const crypto = require('crypto');

const DB = {
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};
const SLACK_WEBHOOK = process.env.SLACK_WEBHOOK;

// ── MySQL client ──────────────────────────────────────────────
function sha1(d){return crypto.createHash('sha1').update(d).digest();}
function sha256(d){return crypto.createHash('sha256').update(d).digest();}
function native(pw,sc){const s1=sha1(Buffer.from(pw)),s2=sha1(s1),s3=sha1(Buffer.concat([sc,s2]));return Buffer.from(s3.map((b,i)=>b^s1[i]));}
function sha2(pw,sc){const h1=sha256(Buffer.from(pw)),h2=sha256(h1),h3=sha256(Buffer.concat([h2,sc]));return Buffer.from(h1.map((b,i)=>b^h3[i]));}
function mkpkt(p,s){const h=Buffer.alloc(4);h[0]=p.length&0xFF;h[1]=(p.length>>8)&0xFF;h[2]=(p.length>>16)&0xFF;h[3]=s;return Buffer.concat([h,p]);}
function rle(buf,off){const f=buf[off];if(f<251)return{v:f,l:1};if(f===251)return{v:null,l:1};if(f===252)return{v:buf.readUInt16LE(off+1),l:3};if(f===253)return{v:buf.readUInt32LE(off+1)&0xFFFFFF,l:4};return{v:Number(buf.readBigUInt64LE(off+1)),l:9};}
function parse(data){const pkts=[];let pos=0;while(pos+4<=data.length){const len=data[pos]|(data[pos+1]<<8)|(data[pos+2]<<16);pos+=4;if(pos+len>data.length)break;pkts.push(data.slice(pos,pos+len));pos+=len;}if(!pkts.length)return[];if(pkts[0][0]===0xFF)throw new Error(pkts[0].slice(9).toString());if(pkts[0][0]===0x00)return[];let pi=1;const fields=[];while(pi<pkts.length&&pkts[pi][0]!==0xFE){const p=pkts[pi++];let o=0;function sk(){const r=rle(p,o);o+=r.l+r.v;}sk();sk();sk();sk();const nr=rle(p,o);o+=nr.l;fields.push(p.slice(o,o+nr.v).toString());o+=nr.v;}pi++;const rows=[];while(pi<pkts.length&&pkts[pi][0]!==0xFE){const p=pkts[pi++];let o=0;const row={};for(const f of fields){const r=rle(p,o);o+=r.l;row[f]=r.v===null?null:p.slice(o,o+r.v).toString();if(r.v!==null)o+=r.v;}rows.push(row);}return rows;}

let conn=null, buf=Buffer.alloc(0), seq=0, state='hs', rb=Buffer.alloc(0);
let currentResolve=null, currentReject=null, queue=[];

function connect(){
  return new Promise((resolve,reject)=>{
    const sock=new net.Socket();
    conn=sock;
    const timer=setTimeout(()=>{sock.destroy();reject(new Error('DB timeout'));},15000);
    sock.connect(DB.port,DB.host);
    sock.on('error',e=>{clearTimeout(timer);reject(e);});
    sock.on('data',c=>{buf=Buffer.concat([buf,c]);pump();});
    function gpkt(){if(buf.length<4)return null;const len=buf[0]|(buf[1]<<8)|(buf[2]<<16);if(buf.length<len+4)return null;seq=buf[3]+1;const p=buf.slice(4,4+len);buf=buf.slice(4+len);return p;}
    function pump(){let p;while((p=gpkt())!==null)handle(p);}
    function handle(pkt){
      if(state==='hs'){const nul=pkt.indexOf(0,1);let pos=nul+1+4;const sc1=pkt.slice(pos,pos+8);pos+=8+1+2+1+2+2+1+10;const sc2=pkt.slice(pos,pos+12);pos+=13;const sc=Buffer.concat([sc1,sc2]);const pe=pkt.indexOf(0,pos);const pl=pkt.slice(pos,pe).toString();const hash=pl==='caching_sha2_password'?sha2(DB.password,sc):native(DB.password,sc);const user=Buffer.from(DB.user+'\0'),db=Buffer.from(DB.database+'\0'),plug=Buffer.from(pl+'\0');sock.write(mkpkt(Buffer.concat([Buffer.from([0x8D,0xA2,0x0F,0x00,0x00,0x00,0x00,0x01,0x21]),Buffer.alloc(23),user,Buffer.from([hash.length]),hash,db,plug]),seq++));state='auth';}
      else if(state==='auth'){if(pkt[0]===0x00){clearTimeout(timer);state='idle';resolve();processQueue();}else if(pkt[0]===0xFE){const nul=pkt.indexOf(0,1);const pl=pkt.slice(1,nul).toString();const d=pkt.slice(nul+1,nul+21);const h=pl==='caching_sha2_password'?sha2(DB.password,d):native(DB.password,d);sock.write(mkpkt(h,seq++));}else if(pkt[0]===0x01&&pkt[1]===0x04){sock.write(mkpkt(Buffer.concat([Buffer.from(DB.password),Buffer.from([0])]),seq++));}}
      else if(state==='querying'){const h=Buffer.alloc(4);h[0]=pkt.length&0xFF;h[1]=(pkt.length>>8)&0xFF;h[2]=(pkt.length>>16)&0xFF;rb=Buffer.concat([rb,h,pkt]);let done=false;if(pkt[0]===0x00){done=true;}else if(pkt[0]===0xFE&&pkt.length<9){let eof=0,p=0;while(p+4<=rb.length){const l=rb[p]|(rb[p+1]<<8)|(rb[p+2]<<16);const pl=rb.slice(p+4,p+4+l);if(pl[0]===0xFE&&l<9)eof++;p+=4+l;}if(eof>=2)done=true;}else if(pkt[0]===0xFF){done=true;}if(done){state='idle';const res=currentResolve,rej=currentReject,rbuf=rb;currentResolve=null;currentReject=null;rb=Buffer.alloc(0);try{res(parse(rbuf));}catch(e){rej(e);}processQueue();}}
    }
  });
}

function processQueue(){if(state!=='idle'||queue.length===0)return;const{sql,resolve,reject}=queue.shift();currentResolve=resolve;currentReject=reject;rb=Buffer.alloc(0);state='querying';const q=Buffer.from(sql);const p=Buffer.alloc(q.length+1);p[0]=0x03;q.copy(p,1);conn.write(mkpkt(p,0));seq=1;}
function query(sql){return new Promise((resolve,reject)=>{queue.push({sql,resolve,reject});if(state==='idle')processQueue();});}
function esc(v){return (v||'').replace(/'/g,"''");}

function getFirstSentence(text){
  if(!text) return '내용 없음';
  const cleaned=String(text).trim();
  const match=cleaned.match(/[^.!?。！？\n]+[.!?。！？]?/);
  return match?match[0].trim():cleaned.slice(0,80);
}

function sendSlack(bug){
  return new Promise((resolve)=>{
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
    const req=https.request({hostname:u.hostname,path:u.pathname+u.search,method:'POST',headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},res=>{resolve(res.statusCode);});
    req.on('error',e=>{console.error('Slack error:',e.message);resolve(null);});
    req.write(body);req.end();
  });
}

async function main(){
  // slack_notified 컬럼 없으면 추가
  try { await query(`ALTER TABLE bug_report_sync ADD COLUMN IF NOT EXISTS slack_notified TINYINT DEFAULT 0`); } catch(e){}

  const rows = await query(`SELECT bug_id, product_name, email, content, created_at FROM bug_report_sync WHERE (slack_notified IS NULL OR slack_notified=0) ORDER BY created_at ASC LIMIT 20`);
  console.log(`미알림 문의: ${rows.length}건`);

  for(const r of rows){
    await sendSlack(r);
    await query(`UPDATE bug_report_sync SET slack_notified=1 WHERE bug_id='${esc(r.bug_id)}'`);
    console.log(`알림 발송: ${r.bug_id} (${r.product_name})`);
  }

  conn.destroy();
  process.exit(0);
}

connect().then(main).catch(e=>{console.error(e.message);process.exit(1);});
