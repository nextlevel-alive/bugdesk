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

function runQuery(sql) {
  return new Promise((resolve, reject) => {
    const sock = new net.Socket();
    let buf = Buffer.alloc(0), seq = 0, state = 'hs', rb = Buffer.alloc(0);
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('DB timeout')); }, 15000);
    sock.connect(DB.port, DB.host);
    sock.on('error', e => { clearTimeout(timer); reject(e); });
    sock.on('data', c => { buf = Buffer.concat([buf, c]); pump(); });
    function gpkt(){if(buf.length<4)return null;const len=buf[0]|(buf[1]<<8)|(buf[2]<<16);if(buf.length<len+4)return null;seq=buf[3]+1;const p=buf.slice(4,4+len);buf=buf.slice(4+len);return p;}
    function pump(){let p;while((p=gpkt())!==null)handle(p);}
    function handle(pkt){
      if(state==='hs'){const nul=pkt.indexOf(0,1);let pos=nul+1+4;const sc1=pkt.slice(pos,pos+8);pos+=8+1+2+1+2+2+1+10;const sc2=pkt.slice(pos,pos+12);pos+=13;const sc=Buffer.concat([sc1,sc2]);const pe=pkt.indexOf(0,pos);const pl=pkt.slice(pos,pe).toString();const hash=pl==='caching_sha2_password'?sha2(DB.password,sc):native(DB.password,sc);const user=Buffer.from(DB.user+'\0'),db=Buffer.from(DB.database+'\0'),plug=Buffer.from(pl+'\0');sock.write(mkpkt(Buffer.concat([Buffer.from([0x8D,0xA2,0x0F,0x00,0x00,0x00,0x00,0x01,0x21]),Buffer.alloc(23),user,Buffer.from([hash.length]),hash,db,plug]),seq++));state='auth';}
      else if(state==='auth'){if(pkt[0]===0x00){state='q';const q=Buffer.from(sql);const p=Buffer.alloc(q.length+1);p[0]=0x03;q.copy(p,1);sock.write(mkpkt(p,0));seq=1;}else if(pkt[0]===0xFE){const nul=pkt.indexOf(0,1);const pl=pkt.slice(1,nul).toString();const d=pkt.slice(nul+1,nul+21);const h=pl==='caching_sha2_password'?sha2(DB.password,d):native(DB.password,d);sock.write(mkpkt(h,seq++));}else if(pkt[0]===0x01&&pkt[1]===0x04){sock.write(mkpkt(Buffer.concat([Buffer.from(DB.password),Buffer.from([0])]),seq++));}}
      else if(state==='q'){const h=Buffer.alloc(4);h[0]=pkt.length&0xFF;h[1]=(pkt.length>>8)&0xFF;h[2]=(pkt.length>>16)&0xFF;rb=Buffer.concat([rb,h,pkt]);let done=false;if(pkt[0]===0x00){done=true;}else if(pkt[0]===0xFE&&pkt.length<9){let eof=0,p=0;while(p+4<=rb.length){const l=rb[p]|(rb[p+1]<<8)|(rb[p+2]<<16);const pl=rb.slice(p+4,p+4+l);if(pl[0]===0xFE&&l<9)eof++;p+=4+l;}if(eof>=2)done=true;}else if(pkt[0]===0xFF){done=true;}if(done){clearTimeout(timer);sock.destroy();try{resolve(parse(rb));}catch(e){reject(e);}}}
    }
  });
}

function sendSlack(cnt) {
  return new Promise((resolve) => {
    const u = new URL(SLACK_WEBHOOK);
    const body = JSON.stringify({
      text: `❤️‍🔥 현재 2일 넘게 응답되지 않은 답변이 ${cnt}건 있습니다.\n고객이 기다리지 않게 서둘러 답변해주세요 !`,
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: `❤️‍🔥 현재 2일 넘게 응답되지 않은 답변이 *${cnt}건* 있습니다.\n고객이 기다리지 않게 서둘러 답변해주세요 !` } },
        { type: 'actions', elements: [{ type: 'button', text: { type: 'plain_text', text: '버그 해결하러 가기', emoji: true }, url: 'https://bugdesk.vercel.app', style: 'primary' }] }
      ]
    });
    const req = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } }, res => { resolve(res.statusCode); });
    req.on('error', e => { console.error('Slack error:', e.message); resolve(null); });
    req.write(body); req.end();
  });
}

async function main() {
  const rows = await runQuery(
    `SELECT COUNT(*) AS cnt FROM bug_report_sync WHERE answered=0 AND created_at >= '2026-06-01' AND created_at <= NOW() - INTERVAL 48 HOUR`
  );
  const cnt = Number(rows[0].cnt);
  console.log(`미답변 48시간 초과: ${cnt}건`);
  if (cnt > 0) {
    const status = await sendSlack(cnt);
    console.log(`Slack 발송 완료 (status: ${status})`);
  } else {
    console.log('미답변 없음 — 알림 생략');
  }
  process.exit(0);
}

main().catch(e => { console.error(e.message); process.exit(1); });
