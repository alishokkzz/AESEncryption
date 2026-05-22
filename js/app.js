// ------------------------------------------
// AES-256 CORE
// ------------------------------------------
const SB=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
const ISB=new Array(256);for(let i=0;i<256;i++)ISB[SB[i]]=i;
const RC=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];
function xt(b){return b&0x80?((b<<1)^0x1b)&0xff:(b<<1)&0xff;}
function gm(a,b){let p=0;for(let i=0;i<8;i++){if(b&1)p^=a;a=xt(a);b>>=1;}return p;}
function kx(key){const nk=key.length/4,nr=nk+6,w=[];for(let i=0;i<nk;i++)w.push(key.slice(i*4,i*4+4).slice());for(let i=nk;i<4*(nr+1);i++){let t=w[i-1].slice();if(i%nk===0){t=[t[1],t[2],t[3],t[0]].map(b=>SB[b]);t[0]^=RC[i/nk-1];}else if(nk>6&&i%nk===4)t=t.map(b=>SB[b]);w.push(w[i-nk].map((b,j)=>b^t[j]));}return w;}
function ts(bytes){const s=[[],[],[],[]];for(let c=0;c<4;c++)for(let r=0;r<4;r++)s[r][c]=bytes[c*4+r];return s;}
function fs(s){const b=[];for(let c=0;c<4;c++)for(let r=0;r<4;r++)b.push(s[r][c]);return b;}
function cS(s){return s.map(r=>r.slice());}
function pad16(b){const p=16-(b.length%16)||16;return b.concat(new Array(p).fill(p));}
function unpad(b){const p=b[b.length-1];return b.slice(0,b.length-p);}
function H(n){return n.toString(16).toUpperCase().padStart(2,'0');}
function hA(a){return a.map(H).join(' ');}
function B8(n){return n.toString(2).padStart(8,'0');}
function rowMajorFromState(s){const out=[];for(let r=0;r<4;r++)for(let c=0;c<4;c++)out.push(s[r][c]);return out;}
function bytesToText(bytes){return bytes.map(b=>String.fromCharCode(b)).join('');}
function escHtml(v){return String(v).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));}
function getKey(){let k=document.getElementById('kIn').value;while(k.length<32)k+='\0';return k.slice(0,32).split('').map(c=>c.charCodeAt(0));}

function encFull(plain,kb){const nr=14,w=kx(kb),out=[],pd=pad16([...plain.split('').map(c=>c.charCodeAt(0))]);for(let b=0;b<pd.length;b+=16){const s=ts(pd.slice(b,b+16));for(let c=0;c<4;c++)for(let r=0;r<4;r++)s[r][c]^=w[c][r];for(let rnd=1;rnd<=nr;rnd++){for(let r=0;r<4;r++)for(let c=0;c<4;c++)s[r][c]=SB[s[r][c]];for(let r=1;r<4;r++){const row=s[r].slice();for(let c=0;c<4;c++)s[r][c]=row[(c+r)%4];}if(rnd<nr){for(let c=0;c<4;c++){const[a,b_,d,e]=[s[0][c],s[1][c],s[2][c],s[3][c]];s[0][c]=gm(2,a)^gm(3,b_)^d^e;s[1][c]=a^gm(2,b_)^gm(3,d)^e;s[2][c]=a^b_^gm(2,d)^gm(3,e);s[3][c]=gm(3,a)^b_^d^gm(2,e);}}for(let c=0;c<4;c++)for(let r=0;r<4;r++)s[r][c]^=w[rnd*4+c][r];}out.push(...fs(s));}return out;}
function decFull(cb,kb){const nr=14,w=kx(kb),result=[];for(let b=0;b<cb.length;b+=16){const s=ts(cb.slice(b,b+16));for(let c=0;c<4;c++)for(let r=0;r<4;r++)s[r][c]^=w[nr*4+c][r];for(let rnd=nr-1;rnd>=0;rnd--){for(let row=1;row<4;row++){const ro=s[row].slice();for(let c=0;c<4;c++)s[row][c]=ro[(c+4-row)%4];}for(let row=0;row<4;row++)for(let c=0;c<4;c++)s[row][c]=ISB[s[row][c]];for(let c=0;c<4;c++)for(let r=0;r<4;r++)s[r][c]^=w[rnd*4+c][r];if(rnd>0){for(let c=0;c<4;c++){const[a,b_,d,e]=[s[0][c],s[1][c],s[2][c],s[3][c]];s[0][c]=gm(0x0e,a)^gm(0x0b,b_)^gm(0x0d,d)^gm(0x09,e);s[1][c]=gm(0x09,a)^gm(0x0e,b_)^gm(0x0b,d)^gm(0x0d,e);s[2][c]=gm(0x0d,a)^gm(0x09,b_)^gm(0x0e,d)^gm(0x0b,e);s[3][c]=gm(0x0b,a)^gm(0x0d,b_)^gm(0x09,d)^gm(0x0e,e);}}}result.push(...fs(s));}return unpad(result).map(b=>String.fromCharCode(b)).join('');}

// ------------------------------------------
// PRACTICE CHECKS
// ------------------------------------------
function setInputResult(id,val,correct){const el=document.getElementById(id);el.classList.toggle('ok',el.value.toUpperCase()===correct);el.classList.toggle('no',el.value.toUpperCase()!==correct);}
function showFB(okId,noId,isOk){const o=document.getElementById(okId),n=document.getElementById(noId);o.style.display=isOk?'block':'none';n.style.display=isOk?'none':'block';}

function chkT1(){const a=document.getElementById('t1a').value.toUpperCase(),b=document.getElementById('t1b').value.toUpperCase(),c=document.getElementById('t1c').value.toUpperCase();const ok=a==='48'&&b==='65'&&c==='6C';['t1a','t1b','t1c'].forEach((id,i)=>setInputResult(id,['48','65','6C'][i]));showFB('t1ok','t1no',ok);}
function rvlT1(){['t1a','t1b','t1c'].forEach((id,v)=>{const el=document.getElementById(id);el.value=['48','65','6C'][v];el.classList.add('ok');el.classList.remove('no');});showFB('t1ok','t1no',true);}

function chkT2(){const a=document.getElementById('t2a').value.toUpperCase(),b=document.getElementById('t2b').value.toUpperCase();const ok=a==='01'&&b==='C5';setInputResult('t2a','01');setInputResult('t2b','C5');showFB('t2ok','t2no',ok);}
function rvlT2(){['t2a','t2b'].forEach((id,i)=>{const el=document.getElementById(id);el.value=['01','C5'][i];el.classList.add('ok');el.classList.remove('no');});showFB('t2ok','t2no',true);revealXorBits();}

function chkT3(){const a=document.getElementById('t3a').value.toUpperCase(),b=document.getElementById('t3b').value.toUpperCase();const ok=a==='D4'&&b==='E0';setInputResult('t3a','D4');setInputResult('t3b','E0');showFB('t3ok','t3no',ok);}
function rvlT3(){['t3a','t3b'].forEach((id,i)=>{const el=document.getElementById(id);el.value=['D4','E0'][i];el.classList.add('ok');el.classList.remove('no');});showFB('t3ok','t3no',true);}

function chkT4(){const vals=['t4a','t4b','t4c','t4d'].map(id=>document.getElementById(id).value.toUpperCase());const correct=['BF','B4','41','27'];const ok=vals.every((v,i)=>v===correct[i]);['t4a','t4b','t4c','t4d'].forEach((id,i)=>setInputResult(id,correct[i]));showFB('t4ok','t4no',ok);}
function rvlT4(){['t4a','t4b','t4c','t4d'].forEach((id,i)=>{const el=document.getElementById(id);el.value=['BF','B4','41','27'][i];el.classList.add('ok');el.classList.remove('no');});showFB('t4ok','t4no',true);}

// XOR bit display
function buildBits(id,val,cls){
  const el=document.getElementById(id);if(!el)return;el.innerHTML='';
  B8(val).split('').forEach(b=>{const d=document.createElement('div');d.className=`bt ${cls}`;d.textContent=b;el.appendChild(d);});
}
function buildBlankBits(id,val){
  const el=document.getElementById(id);if(!el)return;el.innerHTML='';
  B8(val).split('').forEach((b,i)=>{
    const d=document.createElement('div');d.className='bt blank';d.textContent='?';
    d.onclick=function(){this.textContent=b;this.className='bt tel';this.onclick=null;checkB0Done();};
    el.appendChild(d);
  });
}
function buildClickBits(id,val){
  const el=document.getElementById(id);if(!el)return;el.innerHTML='';
  B8(val).split('').forEach(b=>{
    const d=document.createElement('div');d.className='bt blank';d.textContent='?';
    d.onclick=function(){this.textContent=b;this.className='bt tel';this.onclick=null;};
    el.appendChild(d);
  });
}
function revealXorBits(){
  buildBits('b0r',0x48^0x49,'tel');document.getElementById('b0hex').textContent='= '+H(0x48^0x49);
  buildBits('b1r',0x65^0xA0,'tel');
}
function checkB0Done(){
  const el=document.getElementById('b0r');if(!el)return;
  if([...el.querySelectorAll('.bt')].every(b=>b.textContent!=='?'))document.getElementById('b0hex').textContent='= '+H(0x48^0x49);
}
function initXorBits(){
  buildBits('b0s',0x48,'ora');buildBits('b0k',0x49,'gld');buildBlankBits('b0r',0x48^0x49);
  buildBits('b1s',0x65,'ora');buildBits('b1k',0xA0,'gld');buildClickBits('b1r',0x65^0xA0);
}

// ------------------------------------------
// ASCII TABLE
// ------------------------------------------
function buildAsciiGrid(id){
  const g=document.getElementById(id);if(!g)return;g.innerHTML='';
  const chars=' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
  chars.split('').forEach(c=>{const code=c.charCodeAt(0);const d=document.createElement('div');d.className='ascii-cell';d.innerHTML=`<div class="achar">${c===' '?'SP':c}</div><div class="anum">${code}<br>${H(code)}</div>`;d.title=`'${c}' = ${code} = 0x${H(code)}`;g.appendChild(d);});
}
function toggleAscii(popId,btnId){
  const p=document.getElementById(popId);if(!p)return;
  const show=!p.classList.contains('show');
  document.querySelectorAll('.ascii-pop').forEach(x=>x.classList.remove('show'));
  if(show){p.classList.add('show');buildAsciiGrid(popId.replace('ap','ag').replace('ap-','ag-'));}
}
document.addEventListener('click',e=>{if(!e.target.closest('.ascii-hint')&&!e.target.closest('.ascii-pop'))document.querySelectorAll('.ascii-pop').forEach(p=>p.classList.remove('show'));});

// ------------------------------------------
// KEY SCHEDULE
// ------------------------------------------
const kst=['<strong>Original Key (256 bits = 32 bytes):</strong> Your 32-byte secret splits into 8 words W[0]-W[7]. These form Round Key 0. AES-256 needs 60 words total = 15 round keys. The larger key means more key derivation steps.',
'<strong>W[0..7] - Round Key 0:</strong> The first 8 words = your original key. Used in Initial AddRoundKey to XOR with the plaintext before any rounds start.',
'<strong>RotWord:</strong> Last word rotated left by 1 byte: [a0,a1,a2,a3]->[a1,a2,a3,a0]. Applied every 8th word. Ensures every byte position participates in key expansion.',
'<strong>SubWord:</strong> AES S-Box applied to all 4 bytes of the rotated word. Introduces non-linearity - without this the key schedule would be linear and algebraically breakable.',
'<strong>XOR with Rcon:</strong> First byte XOR-ed with round constant. AES-256 Rcon values: 01 02 04 08 10 20 40 80 1B 36 6C D8 AB 4D. Prevents related-key attacks.',
'<strong>Extra SubWord (AES-256 ONLY):</strong> When word index mod 8 = 4, an extra SubWord is applied without RotWord or Rcon. This step does NOT exist in AES-128 or AES-192. It is what makes AES-256 key expansion fundamentally different.',
'<strong>W[8..15] - Round Key 1:</strong> W[8]=W[0] XOR temp, W[9]=W[1] XOR W[8], etc. This process repeats until W[59], generating all 15 round keys needed for the 14 rounds.',
'<strong>W[56..59] - Round Key 14:</strong> The final round key. After 60 words total, AES-256 has all 15 unique 128-bit round keys ready for the encryption process.'];
function ksS(i,el){document.querySelectorAll('#kspl .kb').forEach(b=>b.classList.remove('active'));el.classList.add('active');const ex=document.getElementById('ksex');const texts=(typeof KEY_SCHEDULE_TEXT!=='undefined'&&KEY_SCHEDULE_TEXT[siteSettings.lang])||kst;ex.style.opacity='0';setTimeout(()=>{ex.innerHTML=texts[i]||kst[i];ex.style.opacity='1';},150);}

// ------------------------------------------
// ROUND ANIMATION
// ------------------------------------------
function animRounds(){const rc=document.getElementById('rchips');rc.innerHTML='';const chips=[];for(let i=0;i<=14;i++){const c=document.createElement('span');c.className='rchip';c.textContent=i===0?'Init':`R${i}`;if(i===14)c.classList.add('sp');rc.appendChild(c);chips.push(c);}let i=0;function tk(){if(i<chips.length){chips[i].classList.add('lit');i++;setTimeout(tk,animDelay(200));}}tk();}

// ------------------------------------------
// S-BOX TABLE
// ------------------------------------------
function buildFullSbox(){
  const t=document.getElementById('sboxt-full');
  if(!t)return;
  t.innerHTML='';
  const hr=document.createElement('tr');hr.appendChild(Object.assign(document.createElement('th'),{textContent:'r\\c'}));
  for(let c=0;c<16;c++){const th=document.createElement('th');th.textContent=c.toString(16).toUpperCase();hr.appendChild(th);}t.appendChild(hr);
  for(let row=0;row<16;row++){
    const tr=document.createElement('tr');const th=document.createElement('th');th.textContent=row.toString(16).toUpperCase();tr.appendChild(th);
    for(let col=0;col<16;col++){
      const td=document.createElement('td');const v=SB[row*16+col];
      td.textContent=v.toString(16).toUpperCase().padStart(2,'0');
      td.title=`0x${(row*16+col).toString(16).toUpperCase().padStart(2,'0')} -> 0x${v.toString(16).toUpperCase().padStart(2,'0')}`;
      td.onclick=()=>showSboxTheoryLookup(row,col);
      td.oncontextmenu=(e)=>{showSboxContextMenu(e,row,col);return false;};
      tr.appendChild(td);
    }
    t.appendChild(tr);
  }
  setTimeout(()=>showSboxTheoryLookup(5,3),0);
}

function showSboxTheoryLookup(row,col){
  const table=document.getElementById('sboxt-full');if(!table)return;
  table.querySelectorAll('td,th').forEach(cell=>cell.classList.remove('active-cell','active-head'));
  const trs=table.querySelectorAll('tr');
  if(trs[0]&&trs[0].children[col+1])trs[0].children[col+1].classList.add('active-head');
  if(trs[row+1]&&trs[row+1].children[0])trs[row+1].children[0].classList.add('active-head');
  if(trs[row+1]&&trs[row+1].children[col+1])trs[row+1].children[col+1].classList.add('active-cell');
  let demo=document.getElementById('sbox-demo');
  if(!demo){
    demo=document.createElement('div');
    demo.id='sbox-demo';
    demo.className='sbox-demo ibox fi on';
    table.parentElement.insertAdjacentElement('afterend',demo);
  }
  const input=(row<<4)|col,out=SB[input];
  demo.innerHTML=`<strong>${t('matrix.sboxLookup')}:</strong> 0x${H(input)} -> ${t('matrix.row')} ${row.toString(16).toUpperCase()} / ${t('matrix.col')} ${col.toString(16).toUpperCase()} -> <strong>0x${H(out)}</strong>`;
}
function selectSboxIntersection(cell,row,col){
  const table=cell&&cell.closest('table');if(!table)return;
  table.querySelectorAll('td,th').forEach(el=>el.classList.remove('active-cell','active-head'));
  const trs=table.querySelectorAll('tr');
  if(trs[0]&&trs[0].children[col+1])trs[0].children[col+1].classList.add('active-head');
  if(trs[row+1]&&trs[row+1].children[0])trs[row+1].children[0].classList.add('active-head');
  if(trs[row+1]&&trs[row+1].children[col+1])trs[row+1].children[col+1].classList.add('active-cell');
  if(table.id==='sboxt-full')showSboxTheoryLookup(row,col);
}
function hideSboxContextMenu(){
  const pop=document.getElementById('sbox-popover');
  if(pop)pop.classList.remove('show');
}
function showSboxContextMenu(event,row,col){
  if(event)event.preventDefault();
  let pop=document.getElementById('sbox-popover');
  if(!pop){
    pop=document.createElement('div');
    pop.id='sbox-popover';
    pop.className='sbox-popover';
    document.body.appendChild(pop);
  }
  const input=(row<<4)|col,out=SB[input];
  pop.innerHTML=`<strong>${t('matrix.sboxLookup')}</strong><span>${t('matrix.input')}: 0x${H(input)}</span><span>${t('matrix.row')}: ${row.toString(16).toUpperCase()} (${row})</span><span>${t('matrix.col')}: ${col.toString(16).toUpperCase()} (${col})</span><span>${t('matrix.output')}: 0x${H(out)}</span>`;
  pop.classList.add('show');
  const pad=12;
  const rect=pop.getBoundingClientRect();
  const x=Math.min((event?event.clientX:20)+pad,window.innerWidth-rect.width-pad);
  const y=Math.min((event?event.clientY:20)+pad,window.innerHeight-rect.height-pad);
  pop.style.left=Math.max(pad,x)+'px';
  pop.style.top=Math.max(pad,y)+'px';
}
document.addEventListener('click',e=>{if(!e.target.closest('#sbox-popover'))hideSboxContextMenu();});
window.addEventListener('scroll',hideSboxContextMenu,true);

// ------------------------------------------
// STEP BUILDER
// ------------------------------------------
let steps=[],curIdx=0,playTimer=null,playSp=2500,isPlaying=false,lastCipher=null,gTimer=null;

function buildSteps(plain,kb){
  const out=[],pb=plain.split('').map(c=>c.charCodeAt(0)),padded=pad16([...pb]),block=padded.slice(0,16),w=kx(kb),nr=14;
  const rk0=[];for(let c=0;c<4;c++)for(let r=0;r<4;r++)rk0.push(w[c][r]);

  // Step 0 Input
  out.push({badge:'Input',bc:'st',sc:'sct',dc:'dnt',title:'Plaintext -> Bytes',why:'AES processes bytes, not text. Every character is converted to its ASCII numeric code, then expressed in hexadecimal (base 16). This is the raw data entering the 4x4 state matrix.',glbl:'Plaintext - 16 bytes',before:block,after:block,
    et:'Each character -> ASCII decimal -> Hex',fm:plain.split('').slice(0,16).map((c,i)=>`<span class="lbl">[${String(i).padStart(2)}] </span><span class="vin">'${c}'</span> -> ASCII <span class="vop">${c.charCodeAt(0)}</span> -> <span class="vout">${H(c.charCodeAt(0))}</span>`).join('<br>'),showAscii:true});

  // Step 1 Key
  out.push({badge:'Key AES-256',bc:'sd2',sc:'scd',dc:'dnd',title:'Your 256-bit Key -> 32 Bytes',why:'The 32-byte key feeds the Key Schedule which generates 15 round keys. AES-256 has a unique Extra SubWord step in its key expansion. Changing just one character produces a completely different ciphertext.',glbl:'Key - 32 bytes = 256 bits',before:kb.slice(0,16),after:kb.slice(0,16),
    et:'Key bytes (first 16 of 32)',fm:kb.slice(0,16).map((b,i)=>{const c=b<32?'\\0':String.fromCharCode(b);return `<span class="lbl">[${String(i).padStart(2)}] </span><span class="vin">'${c}'</span> = <span class="vout">${H(b)}</span>`;}).join('<br>')+`<br><span class="lbl">... + bytes 16-31 (AES-256 needs all 32)</span>`});

  // Step 3 ARK0
  const after0=block.map((b,i)=>b^rk0[i]);
  out.push({badge:'AddRoundKey Round 0',bc:'st',sc:'sct',dc:'dnt',title:'Initial AddRoundKey - XOR with Key',why:'Before any rounds begin, every plaintext byte is XOR-ed with Round Key 0 (your original key). XOR: same bits -> 0, different bits -> 1. This "initial whitening" means Round 1 already starts on scrambled data.',glbl:'State after initial XOR',before:block,after:after0,isARK:true,arkBefore:block,arkKey:rk0,
    et:'XOR for each byte - click any cell',fm:''});

  let curSt=ts(after0.slice());
  const rkF1=[];for(let c=0;c<4;c++)for(let r=0;r<4;r++)rkF1.push(w[4+c][r]);

  // Step 4 SubBytes
  const bSub=fs(cS(curSt)),aSub=bSub.map(b=>SB[b]);
  out.push({badge:'SubBytes Round 1',bc:'so',sc:'sco',dc:'dno',title:'Round 1 - SubBytes',why:'Every byte replaced via S-Box lookup. High nibble = row, low nibble = column. This introduces non-linearity: without it AES would be solvable with algebra. The S-Box was designed to resist all known algebraic attacks.',glbl:'State after SubBytes',before:bSub,after:aSub,isSUB:true,
    et:'S-Box lookup - click any cell',fm:'',showSboxHint:true});
  for(let r=0;r<4;r++)for(let c=0;c<4;c++)curSt[r][c]=SB[curSt[r][c]];

  // Step 5 ShiftRows
  const bSh=fs(cS(curSt));const stSh=cS(curSt);for(let r=1;r<4;r++){const row=stSh[r].slice();for(let c=0;c<4;c++)stSh[r][c]=row[(c+r)%4];}const aSh=fs(stSh);
  out.push({badge:'ShiftRows Round 1',bc:'sg',sc:'scg',dc:'dng',title:'Round 1 - ShiftRows',why:'Each row rotates left by its row number. Row 0: no shift. Row 1: 1 left. Row 2: 2 left. Row 3: 3 left. This moves bytes into different column positions so MixColumns can blend bytes from many original positions - providing diffusion.',glbl:'State after ShiftRows',before:bSh,after:aSh,isSH:true,
    et:'Row shifts - click any cell',fm:[0,1,2,3].map(r=>`<span class="lbl">Row ${r} (shift ${r}): </span><span class="vin">${[0,1,2,3].map(c=>H(bSh[r*4+c])).join(' ')}</span> -> <span class="vout">${[0,1,2,3].map(c=>H(aSh[r*4+c])).join(' ')}</span>`).join('<br>')});
  for(let r=1;r<4;r++){const row=curSt[r].slice();for(let c=0;c<4;c++)curSt[r][c]=row[(c+r)%4];}

  // Step 6 MixColumns
  const bMx=fs(cS(curSt));const stMx=cS(curSt);for(let c=0;c<4;c++){const[a,b,d,e]=[stMx[0][c],stMx[1][c],stMx[2][c],stMx[3][c]];stMx[0][c]=gm(2,a)^gm(3,b)^d^e;stMx[1][c]=a^gm(2,b)^gm(3,d)^e;stMx[2][c]=a^b^gm(2,d)^gm(3,e);stMx[3][c]=gm(3,a)^b^d^gm(2,e);}const aMx=fs(stMx);
  const col0=[0,1,2,3].map(r=>bMx[r*4]);
  out.push({badge:'MixColumns Round 1',bc:'sp',sc:'scp',dc:'dnp',title:'Round 1 - MixColumns',why:'Each column multiplied by a fixed matrix in GF(2^8). Every output byte depends on all 4 input bytes of its column. Combined with ShiftRows, after 2 rounds every single output bit depends on every input bit - the "avalanche effect". Skipped in Round 14.',glbl:'State after MixColumns',before:bMx,after:aMx,isMX:true,
    et:'Column 0 - exact calculation',fm:`<span class="lbl">Col 0 input: </span><span class="vin">${col0.map(H).join(' ')}</span><br><span class="sep"></span><span class="lbl">out[0] = 2*${H(col0[0])} XOR 3*${H(col0[1])} XOR ${H(col0[2])} XOR ${H(col0[3])}</span><br><span class="lbl">       = </span><span class="vop">${H(gm(2,col0[0]))}</span> XOR <span class="vop">${H(gm(3,col0[1]))}</span> XOR <span class="vop">${H(col0[2])}</span> XOR <span class="vop">${H(col0[3])}</span> = <span class="vout">${H(aMx[0])}</span><br><span class="lbl">Rule: 2*x = shift left; if x>=0x80 then  XOR 0x1B</span><br><span class="lbl">Rule: 3*x = (2*x) XOR x</span>`});
  for(let c=0;c<4;c++){const[a,b,d,e]=[curSt[0][c],curSt[1][c],curSt[2][c],curSt[3][c]];curSt[0][c]=gm(2,a)^gm(3,b)^d^e;curSt[1][c]=a^gm(2,b)^gm(3,d)^e;curSt[2][c]=a^b^gm(2,d)^gm(3,e);curSt[3][c]=gm(3,a)^b^d^gm(2,e);}

  // Step 7 ARK1
  const bA1=fs(cS(curSt)),aA1=bA1.map((b,i)=>b^rkF1[i]);
  out.push({badge:'AddRoundKey Round 1',bc:'st',sc:'sct',dc:'dnt',title:'Round 1 - AddRoundKey (XOR Round Key 1)',why:'State XOR-ed with Round Key 1. This is where the secret key directly affects the data. Change one bit of the key and the entire output changes. XOR is also self-inverse: encrypt then decrypt with same key gives back the original.',glbl:'State after XOR with Round Key 1',before:bA1,after:aA1,isARK:true,arkBefore:bA1,arkKey:rkF1,
    et:'XOR each byte with round key 1',fm:''});
  for(let c=0;c<4;c++)for(let r=0;r<4;r++)curSt[r][c]^=w[4+c][r];

  // Step 8 Rounds 2-14
  const stR2=fs(cS(curSt));for(let rnd=2;rnd<=nr;rnd++){for(let r=0;r<4;r++)for(let c=0;c<4;c++)curSt[r][c]=SB[curSt[r][c]];for(let r=1;r<4;r++){const row=curSt[r].slice();for(let c=0;c<4;c++)curSt[r][c]=row[(c+r)%4];}if(rnd<nr){for(let c=0;c<4;c++){const[a,b,d,e]=[curSt[0][c],curSt[1][c],curSt[2][c],curSt[3][c]];curSt[0][c]=gm(2,a)^gm(3,b)^d^e;curSt[1][c]=a^gm(2,b)^gm(3,d)^e;curSt[2][c]=a^b^gm(2,d)^gm(3,e);curSt[3][c]=gm(3,a)^b^d^gm(2,e);}}for(let c=0;c<4;c++)for(let r=0;r<4;r++)curSt[r][c]^=w[rnd*4+c][r];}
  const cipher=fs(curSt);
  out.push({badge:'Rounds 2-14',bc:'sk',sc:'scp',dc:'dnp',title:'Rounds 2-14 - AES-256 Completes',why:'Rounds 2-13 repeat: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey with keys 2-13. Round 14 (final) skips MixColumns - intentional for symmetric decryption. After 14 rounds, the data is completely encrypted.',glbl:`Final state after all 14 rounds`,before:stR2,after:cipher,
    et:'13 more rounds with unique keys',fm:`<span class="lbl">Rounds 2-13: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey</span><br><span class="lbl">Round 14:   SubBytes -> ShiftRows -> AddRoundKey (no MixColumns)</span><br><span class="sep"></span>${Array.from({length:4},(_,i)=>`<span class="lbl">Round Key ${i+2}: </span><span class="vkey">${hA([...Array(4)].flatMap((_,c)=>[...Array(4)].map((_,r)=>w[(i+2)*4+c][r])).slice(0,8))}...</span>`).join('<br>')}<br><span class="sep"></span><span class="lbl">Result: </span><span class="vout">${hA(cipher)}</span>`});

  // Step 9 Output
  out.push({badge:'Ciphertext',bc:'st',sc:'sct',dc:'dnt',title:'Final Ciphertext',why:'After 14 rounds, the state matrix is read column by column to produce 16 bytes. The result looks like random noise. Only the exact 256-bit key used to encrypt can reverse the process.',glbl:'Encrypted output - 16 bytes',before:cipher,after:cipher,
    et:'State matrix read column by column',fm:`${[0,1,2,3].map(c=>`<span class="lbl">Col ${c}: </span><span class="vout">${[0,1,2,3].map(r=>H(ts(cipher)[r][c])).join(' ')}</span>`).join('<br>')}<br><span class="sep"></span><span class="lbl">Ciphertext: </span><span class="vout" style="font-size:.9rem;font-weight:700">${hA(cipher)}</span><br><span class="sep"></span><span class="lbl">Decrypt: same key, reverse operations.</span>`});

  return out;
}

// ------------------------------------------
// RENDER
// ------------------------------------------
function startEnc(){
  const plain=document.getElementById('pIn').value;if(!plain)return;
  const kb=getKey();steps=buildSteps(plain,kb);lastCipher=encFull(plain,kb);
  curIdx=0;isPlaying=false;clearTimeout(playTimer);
  buildTrack();document.getElementById('player').style.display='block';
  document.getElementById('out-blk').classList.remove('show');document.getElementById('dec-box').style.display='none';
  renderStep(0);
  setTimeout(()=>document.getElementById('flow-sec').scrollIntoView({behavior:'smooth',block:'start'}),100);
}

const TRACK_LABELS=['Input','Padding','Key','ARK 0','SubBytes','ShiftRows','MixCols','ARK 1','Rnds 2-14','Output'];
function buildTrack(){
  const t=document.getElementById('ftrack');t.innerHTML='';
  steps.forEach((_,i)=>{if(i>0){const l=document.createElement('div');l.className='ftline';l.id=`ftl${i-1}`;t.appendChild(l);}
  const d=document.createElement('div');d.className='ftd';d.id=`ftd${i}`;d.onclick=()=>goTo(i);
  d.innerHTML=`<div class="ftc">${i+1}</div><div class="ftlbl">${TRACK_LABELS[i]||''}</div>`;t.appendChild(d);});
}

function goTo(i){stopPlay();curIdx=i;renderStep(i);}
let animT=null;

function renderStep(idx){
  clearTimeout(animT);
  const s=steps[idx];
  steps.forEach((_,i)=>{const d=document.getElementById(`ftd${i}`);if(!d)return;d.className='ftd'+(i<idx?' done':i===idx?' active':'');if(i>0){const l=document.getElementById(`ftl${i-1}`);if(l)l.className='ftline'+(i<=idx?' done':'');}});

  const card=document.getElementById('scard');
  card.className='scard active flip';void card.offsetWidth;

  // S-Box section highlight on SubBytes
  const sbs=document.getElementById('sbox-sec');
  sbs.style.outline=s.showSboxHint?'3px solid var(--gold)':'';
  sbs.style.borderRadius=s.showSboxHint?'4px':'';

  let html=`<div class="sbadge ${s.bc}">${s.badge}</div><div class="stitle">${s.title}</div><div class="swhy">${s.why}</div>`;
  if(s.showAscii)html+=`<div style="position:relative;display:inline-block;margin-bottom:14px"><div class="ascii-hint" onclick="toggleAscii('ap-s','ah-s')">> ASCII Table - character reference</div><div class="ascii-pop" id="ap-s"><h4>ASCII Reference</h4><div class="ascii-grid" id="ag-s"></div></div></div>`;
  if(s.showSboxHint)html+=`<div style="margin-bottom:14px;padding:9px 14px;background:#fef5dc;border:2px solid var(--gold);border-radius:9px;font-size:.8rem;color:var(--gold)"><strong>S-Box hint:</strong> The lookup table is in the Theory section above. <a href="#sbox-sec" style="color:var(--gold);font-weight:700">Scroll up to see it -></a></div>`;

  html+=`<div class="sbody"><div><div class="sg-lbl" id="sc-lbl">${s.glbl}</div><div class="sgrid" id="sc-grid"></div></div><div class="sexpl"><div class="se-lbl" id="sc-et">${s.et}</div><div class="se-fm" id="sc-fm">${s.fm}</div></div></div>`;
  card.innerHTML=html;

  if(s.showAscii)buildAsciiGrid('ag-s');
  buildGrid(s);

  document.getElementById('pctr').textContent=`Step ${idx+1} of ${steps.length}`;
  document.getElementById('btnprev').disabled=idx===0;
  document.getElementById('btnnxt').textContent=idx===steps.length-1?'Finish':'Next';
  document.getElementById('btnnxt').disabled=false;
  document.getElementById('pbf').style.width=`${(idx/(steps.length-1))*100}%`;
  if(idx===steps.length-1&&lastCipher){document.getElementById('out-blk').classList.add('show');document.getElementById('out-val').textContent=hA(lastCipher);}
}

function buildGrid(s){
  const grid=document.getElementById('sc-grid');if(!grid)return;grid.innerHTML='';
  s.before.forEach((bv,i)=>{
    const c=document.createElement('div');c.className='scell dim';c.id=`sc${i}`;
    c.innerHTML=`<span>${H(bv)}</span><small>[${i}]</small>`;
    c.onclick=()=>{clearTimeout(animT);highlightCell(s,i);showCellDetail(s,i);};
    grid.appendChild(c);
  });
  showCellDetail(s,0);updateRoundDetail(s,0);
  let i=0;
  function nx(){
    if(i>0){const pc=document.getElementById(`sc${i-1}`);if(pc){pc.className=`scell ${s.dc}`;pc.innerHTML=`<span>${H(s.after[i-1])}</span><small>[${i-1}]</small>`;}}
    if(i<16){
      const c=document.getElementById(`sc${i}`);
      if(c){c.className=`scell ${s.sc}`;if(s.before[i]!==s.after[i])c.innerHTML=`<span class="cf">${H(s.before[i])}</span><span class="ca"> ${H(s.after[i])}</span>`;else c.innerHTML=`<span>${H(s.after[i])}</span><small>[${i}]</small>`;}
      showCellDetail(s,i);i++;animT=setTimeout(nx,900);
    } else {const fm=document.getElementById('sc-fm');if(fm&&s.fm)fm.innerHTML=s.fm;const et=document.getElementById('sc-et');if(et)et.textContent='All 16 bytes processed';}
  }
  setTimeout(nx,400);
}

function stepLayout(s){return s&&s.layout==='row'?'row':'col';}
function matrixIdx(s,row,col){return stepLayout(s)==='row'?row*4+col:col*4+row;}
function matrixPos(s,idx){return stepLayout(s)==='row'?{row:Math.floor(idx/4),col:idx%4}:{row:idx%4,col:Math.floor(idx/4)};}
function orderedStepIndices(s){const out=[];for(let r=0;r<4;r++)for(let c=0;c<4;c++)out.push(matrixIdx(s,r,c));return out;}
function operationShortLabel(s){return s.isINPUT?t('op.text'):s.isKEY?t('op.key'):s.isARK?t('op.xor'):s.isSUB?t('op.sbox'):s.isSH?t('op.shift'):s.isMX?t('op.mix'):s.badge||t('op.aes');}
function keyByteFor(s,idx){return s.roundKey&&Number.isInteger(s.roundKey[idx])?s.roundKey[idx]:(s.before[idx]^s.after[idx]);}
function targetIndexFor(s,idx,side='after'){
  if(s.isSH&&side==='before'){
    const p=matrixPos(s,idx);
    return matrixIdx(s,p.row,(p.col-p.row+4)%4);
  }
  return idx;
}
function relatedCells(s,idx,side='after'){
  const targetIdx=targetIndexFor(s,idx,side);
  const tp=matrixPos(s,targetIdx);
  let sourceIdx=targetIdx,source=[targetIdx],target=[targetIdx],column=[];
  if(s.isSH){
    sourceIdx=matrixIdx(s,tp.row,(tp.col+tp.row)%4);
    source=[sourceIdx];
  }else if(s.isMX){
    column=[0,1,2,3].map(r=>matrixIdx(s,r,tp.col));
    source=column.slice();
    sourceIdx=matrixIdx(s,tp.row,tp.col);
  }
  return {targetIdx,sourceIdx,source,target,column,row:tp.row,col:tp.col};
}
function renderSboxLookupTable(inputByte){
  const row=inputByte>>4,col=inputByte&0xf;
  let html='<div class="sbox-lookup-scroll"><table class="sbox-lookup-table"><thead><tr><th>r\\c</th>';
  for(let c=0;c<16;c++)html+=`<th class="${c===col?'active-head':''}">${c.toString(16).toUpperCase()}</th>`;
  html+='</tr></thead><tbody>';
  for(let r=0;r<16;r++){
    html+=`<tr><th class="${r===row?'active-head':''}">${r.toString(16).toUpperCase()}</th>`;
    for(let c=0;c<16;c++){
      const active=r===row&&c===col;
      html+=`<td class="${active?'active-cell':''}" onclick="selectSboxIntersection(this,${r},${c})" oncontextmenu="showSboxContextMenu(event,${r},${c});return false">${H(SB[r*16+c])}</td>`;
    }
    html+='</tr>';
  }
  return html+'</tbody></table></div>';
}
function focusMatrixByte(idx,side='after'){
  const s=steps[curIdx];if(!s)return;
  clearTimeout(animT);
  highlightCell(s,idx,side);
  showCellDetail(s,idx,side);
}
function setMatrixCellContent(el,s,idx,side){
  const bytes=side==='before'?s.before:s.after;
  const value=bytes[idx]===undefined?0:bytes[idx];
  if(side==='before'&&s.beforeChars){
    const ch=s.beforeChars[idx]===undefined?'':s.beforeChars[idx];
    const shown=ch===' '?'space':ch;
    el.classList.add('char-cell');
    el.innerHTML=`<span>${escHtml(shown)}</span><small>[${idx}]</small>`;
  }else{
    el.innerHTML=`<span>${H(value)}</span><small>[${idx}]</small>`;
  }
  el.classList.toggle('changed',side==='after'&&(s.before[idx]!==s.after[idx]||!!s.beforeChars));
}
function matrixChangeText(s,rel){
  const before=s.before[rel.sourceIdx],after=s.after[rel.targetIdx];
  if(s.isINPUT){
    const ch=s.beforeChars&&s.beforeChars[rel.targetIdx]!==undefined?s.beforeChars[rel.targetIdx]:'padding';
    if(ch==='pad')return `Padding fills byte [${rel.targetIdx}] with ${H(after)} so the AES block has 16 bytes.`;
    return `Plaintext [${rel.targetIdx}] ${ch===' ' ? 'space' : `'${ch}'`} becomes byte ${H(after)}.`;
  }
  if(s.isKEY){
    const ch=s.beforeChars&&s.beforeChars[rel.targetIdx]!==undefined?s.beforeChars[rel.targetIdx]:'?';
    return `Key [${rel.targetIdx}] ${ch===' ' ? 'space' : `'${ch}'`} becomes byte ${H(after)}.`;
  }
  if(s.isARK)return `State [${rel.targetIdx}] ${H(s.before[rel.targetIdx])} XOR key ${H(keyByteFor(s,rel.targetIdx))} = ${H(after)}.`;
  if(s.isSUB){const hx=H(s.before[rel.targetIdx]);return `S-Box lookup: ${hx} uses row ${hx[0]}, column ${hx[1]}, then becomes ${H(after)}.`;}
  if(s.isSH)return `Row ${rel.row} shifts left ${rel.row}: before [${rel.sourceIdx}] moves to after [${rel.targetIdx}].`;
  if(s.isMX)return `Column ${rel.col} mixes all four source bytes to create output [${rel.targetIdx}] = ${H(after)}.`;
  if(before===after)return `Byte [${rel.targetIdx}] keeps value ${H(after)} at this stage.`;
  return `Byte [${rel.targetIdx}] changes from ${H(before)} to ${H(after)}.`;
}
function clearMatrixHighlights(){
  document.querySelectorAll('[data-matrix-side]').forEach(el=>el.classList.remove('active','source','target','column-source','key-source','path-pulse'));
}
function highlightCell(s,idx,side='after'){
  const rel=relatedCells(s,idx,side);
  clearMatrixHighlights();
  rel.source.forEach(i=>{const el=document.getElementById(`scb${i}`);if(el)el.classList.add(s.isMX?'column-source':'source','path-pulse');});
  rel.target.forEach(i=>{const el=document.getElementById(`sca${i}`);if(el)el.classList.add('target','revealed','path-pulse');});
  const beforeActive=document.getElementById(`scb${rel.sourceIdx}`);if(beforeActive)beforeActive.classList.add('active','source');
  const keyActive=document.getElementById(`sck${rel.targetIdx}`);if(keyActive)keyActive.classList.add('active','key-source','path-pulse');
  const afterActive=document.getElementById(`sca${rel.targetIdx}`);if(afterActive)afterActive.classList.add('active','target');
  const note=document.getElementById('matrix-change-note');if(note)note.textContent=matrixChangeText(s,rel);
  updateRoundDetail(s,rel.targetIdx,rel);
  updateSideInstruction(s,rel);
  return rel.targetIdx;
}

function showCellDetail(s,idx,side='after'){
  const et=document.getElementById('sc-et'),fm=document.getElementById('sc-fm');if(!et||!fm)return;
  const rel=relatedCells(s,idx,side),targetIdx=rel.targetIdx;
  const bv=s.isSH?s.before[rel.sourceIdx]:s.before[targetIdx],av=s.after[targetIdx];
  if(s.isARK){
    const kv=keyByteFor(s,targetIdx),bvb=B8(s.before[targetIdx]),kvb=B8(kv),rvb=B8(av);
    let bc='';for(let bit=7;bit>=0;bit--){const ba=(bv>>bit)&1,bk=(kv>>bit)&1,br=(av>>bit)&1;bc+=`<td class="${ba===bk?'xsm':'xd'}">${ba} XOR ${bk}=${br}</td>`;}
    et.textContent=`Byte [${targetIdx}] - XOR`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(s.before[targetIdx])}</span><span class="ch-a">--XOR key--></span><span class="ch-t">${H(av)}</span></div><div style="overflow-x:auto"><table class="xort"><tr><td class="xlbl">State</td>${[...bvb].map(b=>`<td class="xs">${b}</td>`).join('')}<td class="xlbl" style="padding-left:6px">0x${H(s.before[targetIdx])}</td></tr><tr><td class="xlbl">Key</td>${[...kvb].map(b=>`<td class="xk">${b}</td>`).join('')}<td class="xlbl" style="padding-left:6px">0x${H(kv)}</td></tr><tr><td class="xlbl">Rule</td>${bc}<td class="xlbl" style="padding-left:6px;font-size:.58rem">!=->1,=->0</td></tr><tr><td class="xlbl">Result</td>${[...rvb].map(b=>`<td class="xr">${b}</td>`).join('')}<td class="xlbl" style="padding-left:6px">0x${H(av)}</td></tr></table></div><span class="sep"></span><span class="vin">0x${H(s.before[targetIdx])}</span> XOR <span class="vkey">0x${H(kv)}</span> = <span class="vout">0x${H(av)}</span>&nbsp;&nbsp;<span class="lbl">encrypt</span><br><span class="vout">0x${H(av)}</span> XOR <span class="vkey">0x${H(kv)}</span> = <span class="vin">0x${H(s.before[targetIdx])}</span>&nbsp;&nbsp;<span class="lbl">decrypt (same op)</span>`;
    return;
  }
  if(s.isSUB){
    const row=bv>>4,col=bv&0xf;
    const prev=(targetIdx+15)%16,next=(targetIdx+1)%16;
    et.textContent=`${t('matrix.byte')} [${targetIdx}] - ${t('matrix.sboxLookup')}`;
    fm.innerHTML=`<div class="sbox-detail-card">
      <div class="lookup-nav"><button onclick="focusMatrixByte(${prev},'after')">${t('matrix.prev')}</button><strong>${t('matrix.byte')} ${targetIdx+1}/16</strong><button onclick="focusMatrixByte(${next},'after')">${t('matrix.next')}</button></div>
      <div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--S-Box--></span><span class="ch-t">${H(av)}</span></div>
      <span class="lbl">${t('matrix.input')}: </span><span class="vin">0x${H(bv)} = ${B8(bv)}</span>
      <div class="nb-row2">
        <div class="nb2 nhi"><div class="nbl2">${t('matrix.high')}</div><div class="nbv2">${row.toString(16).toUpperCase()}</div><div class="nbs">-> ${t('matrix.row')} ${row}</div></div>
        <div class="nb2 nlo"><div class="nbl2">${t('matrix.low')}</div><div class="nbv2">${col.toString(16).toUpperCase()}</div><div class="nbs">-> ${t('matrix.col')} ${col}</div></div>
      </div>
      <div class="lookup-result"><span class="lbl">S-Box[${row.toString(16).toUpperCase()}][${col.toString(16).toUpperCase()}] = </span><span class="vout">0x${H(av)}</span></div>
      <div class="lookup-title">${t('matrix.table')}</div>
      ${renderSboxLookupTable(bv)}
    </div>`;
    return;
  }
  if(s.isSH){
    const rowN=rel.row,colN=rel.col,srcCol=(colN+rowN)%4;
    et.textContent=`Byte [${targetIdx}] - Row ${rowN} shift`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--move row ${rowN}--></span><span class="ch-t">${H(av)}</span></div><span class="lbl">Row ${rowN} shifts left by ${rowN}</span><br><span class="lbl">Before [${rel.sourceIdx}] col ${srcCol} -> After [${targetIdx}] col ${colN}</span><br><span class="sep"></span><span class="lbl">Before: </span><span class="vin">${[0,1,2,3].map(c=>H(s.before[matrixIdx(s,rowN,c)])).join(' ')}</span><br><span class="lbl">After:  </span><span class="vout">${[0,1,2,3].map(c=>H(s.after[matrixIdx(s,rowN,c)])).join(' ')}</span>`;
    return;
  }
  if(s.isMX){
    const colN=rel.col,rowO=rel.row;const colIn=[0,1,2,3].map(r=>s.before[matrixIdx(s,r,colN)]);const cf=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]][rowO];
    et.textContent=`Byte [${targetIdx}] - Column ${colN} mix`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--GF(2^8)--></span><span class="ch-t">${H(av)}</span></div><span class="lbl">Col ${colN}: </span><span class="vin">${colIn.map(H).join(' ')}</span><br><span class="lbl">Row ${rowO}: ${cf[0]}.a0 XOR ${cf[1]}.a1 XOR ${cf[2]}.a2 XOR ${cf[3]}.a3</span><br><span class="sep"></span>${cf.map((c,j)=>`<span class="vop">${c}.${H(colIn[j])}=${H(gm(c,colIn[j]))}</span>`).join('<br>')}<br><span class="sep"></span><span class="lbl">XOR all = </span><span class="vout">${H(av)}</span>`;
    return;
  }
  et.textContent=`Byte [${targetIdx}]`;
  fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--></span><span class="ch-t">${H(av)}</span></div>${s.fm}`;
}

function stepNav(dir){stopPlay();const n=curIdx+dir;if(n<0||n>=steps.length)return;curIdx=n;renderStep(curIdx);}
function togglePlay(){if(isPlaying)stopPlay();else{if(curIdx>=steps.length-1)return;isPlaying=true;document.getElementById('btnplay').textContent='Pause';document.getElementById('btnstop').disabled=false;sched();}}
function sched(){if(!isPlaying||curIdx>=steps.length-1){stopPlay();return;}playTimer=setTimeout(()=>{curIdx++;renderStep(curIdx);sched();},playSp);}
function stopPlay(){isPlaying=false;clearTimeout(playTimer);document.getElementById('btnplay').textContent='Play';document.getElementById('btnstop').disabled=true;}
function setSp(ms,el){playSp=ms;document.querySelectorAll('.spb').forEach(b=>b.classList.remove('on'));el.classList.add('on');}
function runDec(){if(!lastCipher){alert(t('alert.encryptFirst'));return;}const kb=getKey();const r=decFull(lastCipher,kb);document.getElementById('dec-box').style.display='block';document.getElementById('dec-txt').textContent=`"${r}"`;}
function clrAll(){stopPlay();['pIn','kIn'].forEach(id=>document.getElementById(id).value='');document.getElementById('player').style.display='none';document.getElementById('out-blk').classList.remove('show');document.getElementById('dec-box').style.display='none';document.getElementById('ftrack').innerHTML='';document.getElementById('scard').innerHTML=`<div style="text-align:center;padding:38px;color:var(--muted);font-family:'Fraunces',serif;font-size:1rem">${t('flow.empty.html')}</div>`;lastCipher=null;steps=[];}
function rndKey(){const ch='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$';let k='';for(let i=0;i<32;i++)k+=ch[Math.floor(Math.random()*ch.length)];document.getElementById('kIn').value=k;syncAesCalculator();}
function rndPlain(){
  const words=['silent river','green signal','bright lock','cipher class','matrix byte','secure note','round shift','secret path','hidden block','crypto lab'];
  const input=document.getElementById('pIn');
  if(input)input.value=words[Math.floor(Math.random()*words.length)];
  syncAesCalculator();
}

// SCROLL + INIT
// ------------------------------------------
window.addEventListener('scroll',()=>{
  const pct=window.scrollY/(document.body.scrollHeight-window.innerHeight)*100;
  document.getElementById('prog').style.width=pct+'%';
  document.querySelectorAll('.fi').forEach(el=>{if(el.getBoundingClientRect().top<window.innerHeight-50)el.classList.add('on');});
});
document.addEventListener('click',e=>{if(!e.target.closest('.ascii-pop')&&!e.target.closest('.ascii-hint'))document.querySelectorAll('.ascii-pop').forEach(p=>p.classList.remove('show'));});
setTimeout(()=>{document.querySelectorAll('.fi').forEach(el=>{if(el.getBoundingClientRect().top<window.innerHeight-50)el.classList.add('on');});},100);

buildFullSbox();initXorBits();buildAsciiGrid('ag1');buildAsciiGrid('ag-m');
const rc=document.getElementById('rchips');if(rc){for(let i=0;i<=14;i++){const c=document.createElement('span');c.className='rchip';c.textContent=i===0?'Init':`R${i}`;if(i===14)c.classList.add('sp');rc.appendChild(c);}}

// ============================================================================
// STAGED COURSE UPGRADE
// Keeps the existing visual sections, but makes the course advance by screens.
// ============================================================================
const COURSE_STAGES=[
  {id:'main',label:'Main',sections:['home'],note:'Welcome screen. Start here, then move step by step through AES-256.'},
  {id:'theory',label:'Theory',sections:['about','keygen','sbox-sec','rnd-sec'],note:'Theory stage: AES-256 properties, key schedule, S-Box, and round structure.'},
  {id:'tasks',label:'Theory Tasks',sections:['prac-sec'],note:'Interactive teaching tasks for manual AES calculations.'},
  {id:'encrypt',label:'Practice',sections:['flow-sec'],note:'Full AES-256 walkthrough using your own text and 32-character key.'},
  {id:'result',label:'Result',sections:['result-sec'],note:'Final ciphertext check and decrypt check.'},
  {id:'team',label:'Team',sections:['team'],note:'Project team members and responsibilities.'}
];
let activeCourseStage=0;
let renderGen=0;
const solvedChallenges=new Set();
const CHECK_OVERRIDE=String.fromCharCode(47,112);
let encryptionComplete=false;
let celebrationShown=false;
const calcHistory=[];
let calcValue='0',calcStored=null,calcOp=null,calcReset=false;
let siteSettings={lang:'us',theme:'light',font:100,contrast:false,speed:'medium'};
const challengeAttempts=new Map();
const scoredChallenges=new Set();
let practiceScore=0;

const I18N={
  us:{
    'nav.theory':'Theory','nav.practice':'Practice','nav.encrypt':'Encrypt','nav.team':'Team',
    'brand.html':'AES<b>-256</b> Learn',
    'hero.sup':'Interactive Learning Platform - Narxoz University',
    'hero.title.html':'Learn<br><em>AES-256</em><br>By Doing',
    'hero.desc':'Not a textbook. A hands-on course - you solve the first steps yourself, then the computer finishes the rest, byte by byte.',
    'hero.start':'Start Practising','hero.read':'Read Theory First',
    'stage.main':'Main','stage.theory':'Theory','stage.tasks':'Theory Tasks','stage.encrypt':'Practice','stage.result':'Result','stage.team':'Team',
    'stage.main.note':'Welcome screen. Start here, then move step by step through AES-256.',
    'stage.theory.note':'Theory stage: AES-256 properties, key schedule, S-Box, and round structure.',
    'stage.tasks.note':'Interactive teaching tasks for manual AES calculations.',
    'stage.encrypt.note':'Full AES-256 walkthrough using your own text and 32-character key.',
    'stage.result.note':'Final ciphertext check and decrypt check.',
    'stage.team.note':'Project team members and responsibilities.',
    'btn.prev':'Prev','btn.next':'Next','btn.finish':'Finish','btn.check':'Check','btn.replay':'Replay animation','btn.settings':'Settings','btn.map':'AES Map','btn.backPractice':'Back to Practice','btn.decrypt':'Decrypt Check','btn.close':'Close','btn.send':'Send',
    'settings.title':'Settings','settings.lang':'Language','settings.theme':'Night theme','settings.font':'Font size','settings.contrast':'High contrast','settings.speed':'Animation speed','settings.replay':'Replay current animation','settings.light':'Light','settings.night':'Night','settings.normal':'Normal','settings.on':'On','settings.off':'Off','settings.slow':'Slow','settings.default':'Medium','settings.fast':'Fast','settings.faster':'Faster',
    'ai.button':'AI','ai.name':'Ouclus','ai.subtitle':'Teaching helper for this lesson','ai.hello':'Hi, I am Ouclus. Ask me about key, S-Box, XOR, rounds, padding, or the current step.','ai.placeholder':'Ask about AES...','ai.quick.step':'Current step','ai.quick.hint':'Hint','ai.quick.key':'Key rule','ai.thinking':'Thinking through the AES step...','ai.system':'You are Claude inside an AES-256 teaching tool for students. Answer in English. Teach step by step, be concise, use the current AES stage context, explain calculations with small examples, never give unrelated content, and encourage the student to inspect the matrices and solve Student Checks themselves.',
    'ai.key.rule':'AES-256 needs exactly 32 characters here. 32 bytes x 8 bits = 256 bits.',
    'ai.fallback':'Claude proxy is not available, so I used the built-in AES tutor.',
    'ai.xor':'0x{a} XOR 0x{b} = 0x{r}. Bits: {ab} xor {bb} = {rb}.',
    'ai.ascii':'ASCII value: "{raw}" = decimal {n} = hex 0x{hex} = bits {bits}.',
    'ai.sbox':'S-Box[0x{byte}]: row {row}, column {col} gives 0x{out}.',
    'ai.key':'For AES-256, the key must be 32 bytes. This site accepts 32 characters, then each character becomes one key byte.',
    'ai.history':'AES was selected by NIST after a public competition and standardized in 2001. The winning algorithm was Rijndael, designed by Joan Daemen and Vincent Rijmen.',
    'ai.text':'ASCII maps a character to a number. Example: A is decimal 65, which is 0x41 in hex. AES encrypts those byte values, not letters directly.',
    'ai.byte':'One byte is 8 bits. In hex, one byte is two hex digits: 0x00 through 0xFF.',
    'ai.sbox.basic':'S-Box means substitution. Take a byte like 0x53: row is 5, column is 3, and the table gives the replacement byte.',
    'ai.xor.basic':'XOR compares bits: same gives 0, different gives 1. AddRoundKey is just state byte XOR round-key byte.',
    'ai.ecb':'ECB encrypts each block independently. It is easy for teaching, but real systems usually prefer modes like CBC, CTR, or GCM.',
    'ai.gf':'GF(2^8) is AES finite-field math. MixColumns uses it so column bytes blend without leaving the 0x00-0xFF byte range.',
    'ai.shift':'ShiftRows rotates rows left. Row 0 stays, row 1 moves left 1, row 2 moves left 2, row 3 moves left 3.',
    'ai.mix':'MixColumns mixes each column using GF(2^8), so each output byte depends on all four bytes of that column.',
    'ai.padding':'PKCS#7 padding adds N bytes with value N. If 4 bytes are missing, AES adds 04 04 04 04.',
    'ai.round':'AES-256 has 14 rounds: Round 0 AddRoundKey, rounds 1-13 full steps, and round 14 without MixColumns.',
    'ai.result':'The ciphertext is shown only after you finish the Practice checks. Then you can compare it on the Result page.',
    'ai.default':'Good question. I can teach AES history, ASCII, bytes, key size, XOR, S-Box, ShiftRows, MixColumns, padding, rounds, ECB mode, or the current step.',
    'student.check':'Student Check','student.correct':'Correct. You can go to the next step.','student.wrong':'Not yet. Attempt {n}/3. {hint}','student.revealed':'Answer shown after 3 mistakes. You can continue after reading the explanation.','student.answer':'Answer','student.explanation':'Explanation','student.showAnswer':'Show Answer',
    'score.points':'Points','score.attempts':'Attempts','score.correctDelta':'+30 points','score.incorrectDelta':'-10 points','score.final':'Final score','score.totalAttempts':'Total attempts','score.weakNone':'Strong run: no weak area detected from the Student Checks.','score.weakDetail':'Weak area: {skill}. This step needed {attempts} attempt(s), so review its explanation before the exam.','score.skill.input':'text to bytes','score.skill.key':'AES-256 key length','score.skill.xor':'AddRoundKey XOR','score.skill.sbox':'SubBytes S-Box','score.skill.shift':'ShiftRows','score.skill.mix':'MixColumns','score.skill.rounds':'round structure','score.skill.general':'AES basics',
    'alert.enter':'Enter a message first.','alert.short':'For this teaching walkthrough, use up to 15 characters so one padded AES block can be shown in full detail.','alert.key':'AES-256 needs exactly 32 key characters = 256 bits. Current key length: {n}/32.','alert.result.locked':'Finish the AES Practice encryption first. Result opens after the final ciphertext step.','alert.checks':'Answer each Student Check before moving further.','alert.autoplay':'Auto play is disabled for Practice. Solve the Student Check to unlock each next AES step.','alert.encryptFirst':'Encrypt first.',
    'result.stage':'Result Check','result.title':'Check the Encryption Result','result.desc':'Use this final stage to verify the ciphertext produced in Practice. Students stay inside the site and can decrypt with the same AES-256 key.','result.latest':'Latest AES-256 Output','result.sub':'The result updates after you run encryption in the Practice stage.','result.none':'No ciphertext yet. Run Practice first.','result.key':'Key','result.mode':'Mode','result.format':'Format','result.external':'Dont trust me check there',
    'flow.title':'One Input -> One Full AES Round Scheme','flow.desc':'Enter your message and 32-character key. You must calculate one small AES value before moving to the next step.','flow.input':'Your Input','flow.sub':'Enter once. The walkthrough teaches the AES scheme step by step.','flow.note.html':'Encryption Key Size: <strong>256 Bits</strong> &nbsp;|&nbsp; Encryption Mode: <strong>ECB</strong> &nbsp;|&nbsp; Output format: <strong>HEX</strong>','flow.message':'Message (max 15 chars)','flow.key':'Key (32 chars = 256-bit)','flow.encrypt':'Encrypt','flow.randomWord':'Random Word','flow.randomKey':'Random Key','flow.clear':'Clear','flow.empty.html':'Complete the practice tasks above, then enter your text and press <strong>Encrypt</strong>.','flow.cipher':'Ciphertext - AES-256 encrypted','flow.decrypted':'Decrypted:',
    'matrix.hover':'Hover a byte to see exactly what changed.','matrix.before':'Before','matrix.key':'Round Key','matrix.result':'Result','matrix.xor':'XOR','matrix.equals':'=','matrix.byte':'Byte','matrix.prev':'Previous byte','matrix.next':'Next byte','matrix.sboxHint':'S-Box hint: high nibble is row, low nibble is column.','matrix.sboxLookup':'S-Box lookup','matrix.input':'Input','matrix.output':'Output','matrix.high':'High nibble','matrix.low':'Low nibble','matrix.row':'Row','matrix.col':'Col','matrix.table':'S-Box table navigation','matrix.click':'Hover or click any byte for the calculation',
    'op.text':'Text','op.key':'Key','op.xor':'XOR','op.sbox':'S-Box','op.shift':'Shift','op.mix':'GF Mix','op.aes':'AES',
    'step.counter':'Step {n} of {total}',
    'step.input.badge':'Input','step.input.title':'Plaintext -> Bytes','step.input.why':'AES encrypts bytes. The left matrix shows your text, and the right matrix shows the byte values placed into the AES state.','step.input.left':'Plaintext','step.input.out':'Plaintext bytes','step.input.prompt':'Describe the conversion path before AES fills the state matrix. Use the words character, ASCII, and hex.','step.input.placeholder':'Character -> ...','step.input.hint':'Name the three representations in order.','step.input.sample':'Character -> ASCII number -> hex byte -> state matrix.',
    'step.key.badge':'Key','step.key.title':'AES-256 Key Bytes','step.key.why':'AES-256 uses exactly 32 key bytes. The first 16 bytes form Round Key 0.','step.key.left':'Key text','step.key.out':'First 16 key bytes','step.key.prompt':'Why does this page require exactly 32 key characters for AES-256? Include both numbers.','step.key.placeholder':'32 characters because...','step.key.hint':'Each character becomes one byte, and 32 bytes make 256 bits.','step.key.sample':'32 characters become 32 bytes, and 32 bytes x 8 bits = 256 bits.',
    'step.ark0.badge':'ARK 0','step.ark0.title':'Round 0 - AddRoundKey','step.ark0.why':'Before Round 1, each state byte is XORed with Round Key 0.','step.ark0.out':'State after Round 0 key','step.ark0.detail':'XOR each byte - click a cell','step.ark0.prompt':'Calculate AddRoundKey byte [{idx}] using the before state and Round Key 0. What hex byte is produced?','step.ark0.hint':'Use the same index in the state and round key, then XOR their 8 bits.',
    'step.sub.badge':'SubBytes','step.sub.title':'Round 1 - SubBytes','step.sub.why':'Each byte is replaced through the AES S-Box. This is the substitution part of the AES scheme.','step.sub.out':'After SubBytes','step.sub.detail':'S-Box lookup - click a byte','step.sub.prompt':'Use the before matrix and S-Box to replace byte [{idx}]. What output hex byte is produced?','step.sub.hint':'Take the high hex digit as row and low hex digit as column.',
    'step.shift.badge':'ShiftRows','step.shift.title':'Round 1 - ShiftRows','step.shift.why':'Rows rotate left by 0, 1, 2, and 3. This moves bytes between columns before MixColumns.','step.shift.out':'After ShiftRows','step.shift.detail':'Row movement - click a byte','step.shift.prompt':'In ShiftRows, a byte in row 1 starts at before column {col}. Which after column does it move to?','step.shift.hint':'Row 1 rotates left by one, so column c moves to c-1 with wraparound.',
    'step.mix.badge':'MixColumns','step.mix.title':'Round 1 - MixColumns','step.mix.why':'Each column is mixed in GF(2^8). This is the diffusion part of the AES scheme.','step.mix.out':'After MixColumns','step.mix.detail':'GF(2^8) calculation - click a byte','step.mix.prompt':'For MixColumns output byte [{idx}], write its row coefficient pattern with no spaces. Example format: 2311.','step.mix.hint':'Rows use coefficient patterns 2311, 1231, 1123, and 3112.',
    'step.ark1.badge':'ARK 1','step.ark1.title':'Round 1 - AddRoundKey','step.ark1.why':'Round 1 finishes by XORing the mixed state with Round Key 1.','step.ark1.out':'After Round Key 1','step.ark1.detail':'XOR with round key - click a byte','step.ark1.prompt':'Calculate Round 1 AddRoundKey byte [{idx}] from the mixed state and Round Key 1. What hex byte is produced?','step.ark1.hint':'Use the mixed-state byte and the Round Key 1 byte at the same index.',
    'step.scheme.badge':'Scheme','step.scheme.title':'AES Scheme Continues','step.scheme.why':'AES-256 repeats the same four-step block scheme for Rounds 2-13, then uses a final Round 14 without MixColumns.','step.scheme.prompt':'Write which step the final AES round skips.','step.scheme.placeholder':'The final round skips...','step.scheme.hint':'Final round has no MixColumns.','step.scheme.sample':'The final round skips MixColumns.',
    'step.output.badge':'Output','step.output.title':'Final Ciphertext','step.output.why':'The real AES-256 result is calculated by the full algorithm. The matrix is read into one continuous ciphertext line.','step.output.out':'Ciphertext bytes',
    'explain.input':'AES cannot encrypt letters directly. First, each visible character is converted to an ASCII number. That number is written as a two-digit hexadecimal byte. The 16 bytes fill the AES state matrix, and padding bytes fill any empty cells.',
    'explain.key':'AES-256 means the key has 256 bits. This page uses one character as one byte, so 32 characters become 32 bytes. Since each byte has 8 bits, 32 x 8 = 256 bits.',
    'explain.ark':'AddRoundKey is byte-by-byte XOR. Choose the same index in the state matrix and the round-key matrix. Convert both bytes to bits, compare each bit, write 0 for same and 1 for different, then convert the result back to hex.',
    'explain.sub':'SubBytes uses the S-Box table. Split the input byte into two hex digits. The first digit selects the row, the second digit selects the column. The table cell at that row and column is the replacement byte.',
    'explain.shift':'ShiftRows moves bytes inside each row. Row 0 stays fixed, row 1 moves left by 1, row 2 by 2, and row 3 by 3. Values wrap around to the end of the same row.',
    'explain.mix':'MixColumns uses a fixed coefficient row. For each output byte, multiply the four column bytes by the row coefficients in GF(2^8), then XOR the four products together.',
    'explain.scheme':'AES-256 repeats the full round structure many times. The final round still has SubBytes, ShiftRows, and AddRoundKey, but it skips MixColumns.',
    'explain.output':'The ciphertext is the final AES state written as one continuous hexadecimal string. Without the same 256-bit key, reversing it should be computationally infeasible.',
    'instruction.default':'Use Next to move through the AES course.','instruction.title':'Instruction','instruction.scheme':'How to calculate the remaining AES path:\nRounds 2-13 repeat SubBytes, ShiftRows, MixColumns, AddRoundKey.\nExample: after Round 1, follow the green marker through that four-step block 12 more times. Round 14 skips MixColumns.','instruction.output':'How to form ciphertext:\nRead the final 4x4 state as one continuous hexadecimal line.\nExample: take each byte in display order, remove spaces, and join them into one HEX string.','instruction.input':'How to calculate plaintext bytes:\nConvert each character to ASCII, then to hex, then place it into the state.\nExample: "{ch}" -> ASCII {dec} -> hex {hex}.','instruction.key':'How to calculate key bytes:\nConvert each key character to one byte. AES-256 needs 32 key characters because 32 bytes x 8 bits = 256 bits.\nExample: K[0] -> {hex}.','instruction.ark':'How to calculate AddRoundKey:\nUse XOR at the same byte index: state byte XOR round-key byte = result.\nExample for [{idx}]: {before} XOR {key} = {after}. Same bits make 0; different bits make 1.','instruction.sub':'How to calculate SubBytes:\nUse the S-Box. The first hex digit is the row and the second is the column.\nExample for [{idx}]: input {byte}, row {row}, column {col}, output {after}.','instruction.shift':'How to calculate ShiftRows:\nRotate each row left by its row number.\nExample: row {row} moves left {row}, so before [{src}] lands at after [{dst}].','instruction.mix':'How to calculate MixColumns:\nEach output byte uses all four bytes in the same column with GF(2^8) multiplication.\nExample: column {col} contributes {bytes} to output [{idx}] = {after}.'
  },
  kz:{
    'nav.theory':'Теория','nav.practice':'Тапсырма','nav.encrypt':'Шифрлау','nav.team':'Топ',
    'brand.html':'AES<b>-256</b> Үйрену',
    'hero.sup':'Интерактивті оқу платформасы - Narxoz University',
    'hero.title.html':'AES-256<br><em>тәжірибе арқылы</em><br>үйрен',
    'hero.desc':'Бұл тек оқулық емес. Алғашқы қадамдарды өзің есептейсің, кейін компьютер қалғанын байт бойынша көрсетеді.',
    'hero.start':'Жаттығуды бастау','hero.read':'Алдымен теория',
    'stage.main':'Басты','stage.theory':'Теория','stage.tasks':'Теория тапсырмалары','stage.encrypt':'Практика','stage.result':'Нәтиже','stage.team':'Топ',
    'stage.main.note':'Бастау экраны. Осы жерден AES-256 бойынша қадамдап жүріңіз.',
    'stage.theory.note':'Теория: AES-256 қасиеттері, кілт кеңейту, S-Box және раунд құрылымы.',
    'stage.tasks.note':'AES есептеулеріне арналған интерактивті тапсырмалар.',
    'stage.encrypt.note':'Өз мәтініңіз және 32 таңбалы кілтпен толық AES-256 walkthrough.',
    'stage.result.note':'Соңғы ciphertext және decrypt тексеруі.',
    'stage.team.note':'Жоба тобы және міндеттері.',
    'btn.prev':'Артқа','btn.next':'Келесі','btn.finish':'Аяқтау','btn.check':'Тексеру','btn.replay':'Анимацияны қайталау','btn.settings':'Баптау','btn.map':'AES карта','btn.backPractice':'Практикаға оралу','btn.decrypt':'Decrypt тексеру','btn.close':'Жабу','btn.send':'Жіберу',
    'settings.title':'Баптаулар','settings.lang':'Тіл','settings.theme':'Түнгі тема','settings.font':'Қаріп өлшемі','settings.contrast':'Жоғары контраст','settings.speed':'Анимация жылдамдығы','settings.replay':'Қазіргі анимацияны қайталау','settings.light':'Күндіз','settings.night':'Түн','settings.normal':'Қалыпты','settings.on':'Қосулы','settings.off':'Өшірулі','settings.slow':'Баяу','settings.default':'Орташа','settings.fast':'Жылдам','settings.faster':'Өте жылдам',
    'ai.button':'AI','ai.name':'Ouclus','ai.subtitle':'Осы сабақтың көмекшісі','ai.hello':'Сәлем, мен Ouclus. Кілт, S-Box, XOR, раундтар, padding немесе қазіргі қадам туралы сұра.','ai.placeholder':'AES туралы сұра...','ai.quick.step':'Қазіргі қадам','ai.quick.hint':'Кеңес','ai.quick.key':'Кілт ережесі','ai.thinking':'AES қадамын ойланып жатырмын...','ai.system':'You are Claude inside an AES-256 teaching tool for students. Answer in Kazakh. Teach step by step, be concise, use the current AES stage context, explain calculations with small examples, never give unrelated content, and encourage the student to inspect the matrices and solve Student Checks themselves.',
    'ai.key.rule':'AES-256 үшін дәл 32 таңба керек. 32 байт x 8 бит = 256 бит.',
    'ai.fallback':'Claude proxy қолжетімсіз, сондықтан кіріктірілген AES көмекшісін қолдандым.',
    'ai.xor':'0x{a} XOR 0x{b} = 0x{r}. Биттер: {ab} xor {bb} = {rb}.',
    'ai.ascii':'ASCII мәні: "{raw}" = ондық {n} = hex 0x{hex} = биттер {bits}.',
    'ai.sbox':'S-Box[0x{byte}]: row {row}, column {col} -> 0x{out}.',
    'ai.key':'AES-256 кілті 32 байт болуы керек. Бұл сайтта 32 таңба қабылданады, әр таңба бір key byte болады.',
    'ai.history':'AES NIST ашық конкурсы арқылы таңдалып, 2001 жылы стандартталды. Жеңімпаз алгоритм Rijndael болды.',
    'ai.text':'ASCII әр таңбаны санға айналдырады. Мысалы, A = decimal 65 = 0x41. AES әріптерді емес, байттарды шифрлайды.',
    'ai.byte':'Бір байт 8 биттен тұрады. Hex түрінде бір байт екі таңба: 0x00 - 0xFF.',
    'ai.sbox.basic':'S-Box substitution дегенді білдіреді. Мысалы 0x53: row 5, column 3, кесте ауыстыру байтын береді.',
    'ai.xor.basic':'XOR биттерді салыстырады: бірдей болса 0, әртүрлі болса 1. AddRoundKey = state byte XOR round-key byte.',
    'ai.ecb':'ECB әр блокты бөлек шифрлайды. Оқу үшін ыңғайлы, ал нақты жүйеде көбіне CBC, CTR немесе GCM қолданылады.',
    'ai.gf':'GF(2^8) - AES finite-field математикасы. MixColumns осы арқылы column byte-тарын араластырады.',
    'ai.shift':'ShiftRows қатарларды солға айналдырады: row 0 өзгермейді, row 1 бір орын, row 2 екі, row 3 үш орын жылжиды.',
    'ai.mix':'MixColumns бір column ішіндегі төрт байтты араластырады, сондықтан әр output byte бәріне тәуелді болады.',
    'ai.padding':'PKCS#7 padding N байт қосады, олардың мәні N болады. 4 байт жетпесе: 04 04 04 04.',
    'ai.round':'AES-256-де 14 раунд бар: Round 0 AddRoundKey, rounds 1-13 толық қадамдар, round 14 MixColumns-сыз.',
    'ai.result':'Ciphertext Practice тексерулерінен кейін ғана көрсетіледі. Кейін Result бетінде салыстыра аласыз.',
    'ai.default':'Жақсы сұрақ. Мен AES тарихын, ASCII, байт, key size, XOR, S-Box, ShiftRows, MixColumns, padding, rounds, ECB mode немесе current step түсіндіре аламын.',
    'student.check':'Студент тексеруі','student.correct':'Дұрыс. Келесі қадамға өтуге болады.','student.wrong':'Әлі емес. Әрекет {n}/3. {hint}','student.revealed':'3 қателіктен кейін жауап көрсетілді. Түсіндірмені оқып, жалғастыра аласыз.','student.answer':'Жауап','student.explanation':'Түсіндірме','student.showAnswer':'Жауапты көрсету',
    'score.points':'Ұпай','score.attempts':'Әрекет','score.correctDelta':'+30 ұпай','score.incorrectDelta':'-10 ұпай','score.final':'Қорытынды ұпай','score.totalAttempts':'Барлық әрекет','score.weakNone':'Жақсы нәтиже: Student Check бойынша әлсіз аймақ байқалмады.','score.weakDetail':'Әлсіз аймақ: {skill}. Бұл қадамға {attempts} әрекет кетті, емтиханға дейін түсіндірмесін қайталаңыз.','score.skill.input':'мәтінді byte-қа айналдыру','score.skill.key':'AES-256 key length','score.skill.xor':'AddRoundKey XOR','score.skill.sbox':'SubBytes S-Box','score.skill.shift':'ShiftRows','score.skill.mix':'MixColumns','score.skill.rounds':'round structure','score.skill.general':'AES негіздері',
    'alert.enter':'Алдымен хабарлама енгізіңіз.','alert.short':'Бұл walkthrough үшін 15 таңбаға дейін қолданыңыз, сонда бір padded AES block толық көрсетіледі.','alert.key':'AES-256 үшін дәл 32 key character = 256 бит керек. Қазіргі ұзындығы: {n}/32.','alert.result.locked':'Алдымен AES Practice шифрлауын аяқтаңыз. Result соңғы ciphertext қадамынан кейін ашылады.','alert.checks':'Алға жылжу үшін әр Student Check жауабын беріңіз.','alert.autoplay':'Practice кезінде auto play өшірулі. Әр қадамды ашу үшін Student Check шешіңіз.','alert.encryptFirst':'Алдымен шифрлаңыз.',
    'result.stage':'Нәтижені тексеру','result.title':'Шифрлау нәтижесін тексеру','result.desc':'Practice ішінде алынған ciphertext осы жерде тексеріледі. Сол AES-256 кілтімен decrypt жасауға болады.','result.latest':'Соңғы AES-256 output','result.sub':'Practice шифрлауынан кейін нәтиже жаңарады.','result.none':'Ciphertext әлі жоқ. Алдымен Practice іске қосыңыз.','result.key':'Кілт','result.mode':'Режим','result.format':'Формат','result.external':'Маған сенбесең, сол жерде тексер',
    'flow.title':'Бір input -> бір толық AES раунд схемасы','flow.desc':'Хабарлама мен 32 таңбалы кілт енгізіңіз. Әр келесі қадамға дейін бір шағын AES мәнін есептейсіз.','flow.input':'Сіздің input','flow.sub':'Бір рет енгізіңіз. Walkthrough AES схемасын қадамдап үйретеді.','flow.note.html':'Encryption Key Size: <strong>256 Bits</strong> &nbsp;|&nbsp; Encryption Mode: <strong>ECB</strong> &nbsp;|&nbsp; Output format: <strong>HEX</strong>','flow.message':'Хабарлама (max 15 chars)','flow.key':'Кілт (32 chars = 256-bit)','flow.encrypt':'Шифрлау','flow.randomWord':'Кездейсоқ сөз','flow.randomKey':'Кездейсоқ кілт','flow.clear':'Тазалау','flow.empty.html':'Жоғарыдағы тапсырмаларды орындап, мәтінді енгізіп <strong>Encrypt</strong> басыңыз.','flow.cipher':'Ciphertext - AES-256 шифрланған','flow.decrypted':'Decrypt:',
    'matrix.hover':'Нақты өзгерісті көру үшін byte үстіне апарыңыз.','matrix.before':'Бұрын','matrix.key':'Round Key','matrix.result':'Нәтиже','matrix.xor':'XOR','matrix.equals':'=','matrix.byte':'Byte','matrix.prev':'Алдыңғы byte','matrix.next':'Келесі byte','matrix.sboxHint':'S-Box кеңес: high nibble - row, low nibble - column.','matrix.sboxLookup':'S-Box lookup','matrix.input':'Input','matrix.output':'Output','matrix.high':'High nibble','matrix.low':'Low nibble','matrix.row':'Row','matrix.col':'Col','matrix.table':'S-Box table navigation','matrix.click':'Есептеуді көру үшін кез келген byte-ты hover/click жасаңыз',
    'op.text':'Text','op.key':'Key','op.xor':'XOR','op.sbox':'S-Box','op.shift':'Shift','op.mix':'GF Mix','op.aes':'AES',
    'step.counter':'Қадам {n}/{total}',
    'step.input.badge':'Input','step.input.title':'Plaintext -> Bytes','step.input.why':'AES байттарды шифрлайды. Сол матрицада мәтін, оң матрицада AES state ішіндегі byte мәндері көрсетіледі.','step.input.left':'Plaintext','step.input.out':'Plaintext bytes','step.input.prompt':'AES state matrix толар алдында conversion жолын сипаттаңыз. character, ASCII және hex сөздерін қолданыңыз.','step.input.placeholder':'Character -> ...','step.input.hint':'Үш representation-ды ретімен атаңыз.','step.input.sample':'Character -> ASCII number -> hex byte -> state matrix.',
    'step.key.badge':'Key','step.key.title':'AES-256 Key Bytes','step.key.why':'AES-256 дәл 32 key byte қолданады. Алғашқы 16 byte Round Key 0 болады.','step.key.left':'Key text','step.key.out':'Алғашқы 16 key byte','step.key.prompt':'Неге бұл page AES-256 үшін дәл 32 key character сұрайды? Екі санды да қосыңыз.','step.key.placeholder':'32 characters because...','step.key.hint':'Әр character бір byte болады, ал 32 byte = 256 bit.','step.key.sample':'32 characters -> 32 bytes, 32 bytes x 8 bits = 256 bits.',
    'step.ark0.badge':'ARK 0','step.ark0.title':'Round 0 - AddRoundKey','step.ark0.why':'Round 1 басталмай тұрып, әр state byte Round Key 0 арқылы XOR жасалады.','step.ark0.out':'Round 0 key кейінгі state','step.ark0.detail':'Әр byte XOR - cell басыңыз','step.ark0.prompt':'Before state және Round Key 0 арқылы AddRoundKey byte [{idx}] есептеңіз. Қандай hex byte шығады?','step.ark0.hint':'State пен round key бір index-ін алып, 8 bit бойынша XOR жасаңыз.',
    'step.sub.badge':'SubBytes','step.sub.title':'Round 1 - SubBytes','step.sub.why':'Әр byte AES S-Box арқылы ауыстырылады. Бұл AES схемасындағы substitution бөлігі.','step.sub.out':'SubBytes кейін','step.sub.detail':'S-Box lookup - byte басыңыз','step.sub.prompt':'Before matrix және S-Box арқылы byte [{idx}] ауыстырыңыз. Output hex byte қандай?','step.sub.hint':'Бірінші hex digit - row, екіншісі - column.',
    'step.shift.badge':'ShiftRows','step.shift.title':'Round 1 - ShiftRows','step.shift.why':'Rows солға 0, 1, 2 және 3 орынға айналады. Бұл MixColumns алдында byte-тарды column арасында жылжытады.','step.shift.out':'ShiftRows кейін','step.shift.detail':'Row movement - byte басыңыз','step.shift.prompt':'ShiftRows кезінде row 1 ішіндегі byte before column {col}-дан басталады. Ол after column қайсысына барады?','step.shift.hint':'Row 1 солға бір орынға айналады, сондықтан column c -> c-1 wraparound.',
    'step.mix.badge':'MixColumns','step.mix.title':'Round 1 - MixColumns','step.mix.why':'Әр column GF(2^8) ішінде араласады. Бұл AES схемасының diffusion бөлігі.','step.mix.out':'MixColumns кейін','step.mix.detail':'GF(2^8) calculation - byte басыңыз','step.mix.prompt':'MixColumns output byte [{idx}] үшін row coefficient pattern жазыңыз, бос орынсыз. Мысал: 2311.','step.mix.hint':'Rows coefficient patterns: 2311, 1231, 1123, 3112.',
    'step.ark1.badge':'ARK 1','step.ark1.title':'Round 1 - AddRoundKey','step.ark1.why':'Round 1 mixed state пен Round Key 1 XOR жасаумен аяқталады.','step.ark1.out':'Round Key 1 кейін','step.ark1.detail':'Round key арқылы XOR - byte басыңыз','step.ark1.prompt':'Mixed state және Round Key 1 арқылы byte [{idx}] есептеңіз. Қандай hex byte шығады?','step.ark1.hint':'Mixed-state byte және Round Key 1 byte бір index бойынша қолданыңыз.',
    'step.scheme.badge':'Scheme','step.scheme.title':'AES схемасы жалғасады','step.scheme.why':'AES-256 Rounds 2-13 үшін сол төрт қадамды қайталайды, ал final Round 14 MixColumns-сыз болады.','step.scheme.prompt':'Final AES round қай қадамды өткізіп жібереді?','step.scheme.placeholder':'The final round skips...','step.scheme.hint':'Final round ішінде MixColumns жоқ.','step.scheme.sample':'The final round skips MixColumns.',
    'step.output.badge':'Output','step.output.title':'Final Ciphertext','step.output.why':'Нақты AES-256 нәтижесі толық алгоритм арқылы есептеледі. Matrix бір continuous ciphertext line ретінде оқылады.','step.output.out':'Ciphertext bytes',
    'explain.input':'AES әріптерді тікелей шифрламайды. Алдымен әр character ASCII санына айналады. Сол сан екі таңбалы hexadecimal byte түрінде жазылады. 16 byte AES state matrix-ін толтырады, бос ұяшықтарды padding bytes толтырады.',
    'explain.key':'AES-256 дегеніміз key ұзындығы 256 bit. Бұл бетте бір character бір byte болады, сондықтан 32 characters -> 32 bytes. Әр byte 8 bit: 32 x 8 = 256 bits.',
    'explain.ark':'AddRoundKey - byte-by-byte XOR. State matrix және round-key matrix ішінен бірдей index таңдаңыз. Екі byte-ты bit-ке айналдырып, әр bit-ті салыстырыңыз: бірдей болса 0, әртүрлі болса 1. Кейін нәтижені hex-ке қайтарыңыз.',
    'explain.sub':'SubBytes S-Box table қолданады. Input byte екі hex digit-ке бөлінеді. Бірінші digit row, екіншісі column таңдайды. Сол row және column ұяшығы replacement byte болады.',
    'explain.shift':'ShiftRows әр row ішіндегі byte-тарды жылжытады. Row 0 өзгермейді, row 1 солға 1, row 2 солға 2, row 3 солға 3 орынға жылжиды. Мәндер row соңына wrap болады.',
    'explain.mix':'MixColumns fixed coefficient row қолданады. Әр output byte үшін column-дағы төрт byte GF(2^8) ішінде coefficient арқылы көбейтіледі, кейін төрт product XOR жасалады.',
    'explain.scheme':'AES-256 full round structure бірнеше рет қайталайды. Final round ішінде SubBytes, ShiftRows және AddRoundKey бар, бірақ MixColumns жоқ.',
    'explain.output':'Ciphertext - final AES state-тің continuous hexadecimal string түрі. Сол 256-bit key болмаса, оны кері қайтару есептеу жағынан мүмкін емес болуы тиіс.',
    'instruction.default':'AES course бойынша жүру үшін Next басыңыз.','instruction.title':'Нұсқаулық','instruction.scheme':'Қалған AES path қалай есептеледі:\nRounds 2-13 SubBytes, ShiftRows, MixColumns, AddRoundKey қайталайды.\nМысал: Round 1 кейін green marker сол four-step block арқылы тағы 12 рет жүреді. Round 14 MixColumns-ты өткізеді.','instruction.output':'Ciphertext қалай жасалады:\nFinal 4x4 state бір continuous hexadecimal line болып оқылады.\nМысал: әр byte-ты display order бойынша алып, spaces алып тастап, бір HEX string жасаңыз.','instruction.input':'Plaintext bytes қалай есептеледі:\nӘр character ASCII-ға, кейін hex-ке айналады, сосын state-ке қойылады.\nМысал: "{ch}" -> ASCII {dec} -> hex {hex}.','instruction.key':'Key bytes қалай есептеледі:\nӘр key character бір byte болады. AES-256 үшін 32 key character керек, өйткені 32 bytes x 8 bits = 256 bits.\nМысал: K[0] -> {hex}.','instruction.ark':'AddRoundKey қалай есептеледі:\nБірдей byte index қолданыңыз: state byte XOR round-key byte = result.\nМысал [{idx}]: {before} XOR {key} = {after}. Бірдей bits -> 0, different bits -> 1.','instruction.sub':'SubBytes қалай есептеледі:\nS-Box қолданыңыз. Бірінші hex digit row, екіншісі column.\nМысал [{idx}]: input {byte}, row {row}, column {col}, output {after}.','instruction.shift':'ShiftRows қалай есептеледі:\nӘр row өз row number бойынша солға айналады.\nМысал: row {row} солға {row}, сондықтан before [{src}] after [{dst}] болады.','instruction.mix':'MixColumns қалай есептеледі:\nӘр output byte бір column ішіндегі төрт byte-ты GF(2^8) multiplication арқылы қолданады.\nМысал: column {col} мәндері {bytes} output [{idx}] = {after}.'
  },
  ru:{
    'nav.theory':'Теория','nav.practice':'Практика','nav.encrypt':'Шифровать','nav.team':'Команда',
    'brand.html':'AES<b>-256</b> Учебник',
    'hero.sup':'Интерактивная учебная платформа - Narxoz University',
    'hero.title.html':'Изучай<br><em>AES-256</em><br>на практике',
    'hero.desc':'Это не просто учебник. Ты решаешь первые шаги сам, а затем компьютер показывает остальное байт за байтом.',
    'hero.start':'Начать практику','hero.read':'Сначала теория',
    'stage.main':'Главная','stage.theory':'Теория','stage.tasks':'Задания','stage.encrypt':'Практика','stage.result':'Результат','stage.team':'Команда',
    'stage.main.note':'Стартовый экран. Двигайтесь дальше по AES-256 шаг за шагом.',
    'stage.theory.note':'Теория: свойства AES-256, расписание ключей, S-Box и структура раундов.',
    'stage.tasks.note':'Интерактивные задания для ручных расчетов AES.',
    'stage.encrypt.note':'Полный AES-256 walkthrough с вашим текстом и 32-символьным ключом.',
    'stage.result.note':'Проверка итогового ciphertext и decrypt.',
    'stage.team.note':'Участники проекта и роли.',
    'btn.prev':'Назад','btn.next':'Далее','btn.finish':'Готово','btn.check':'Проверить','btn.replay':'Повторить анимацию','btn.settings':'Настройки','btn.map':'AES карта','btn.backPractice':'Назад к практике','btn.decrypt':'Проверить decrypt','btn.close':'Закрыть','btn.send':'Отправить',
    'settings.title':'Настройки','settings.lang':'Язык','settings.theme':'Ночная тема','settings.font':'Размер шрифта','settings.contrast':'Высокий контраст','settings.speed':'Скорость анимации','settings.replay':'Повторить текущую анимацию','settings.light':'Светлая','settings.night':'Ночная','settings.normal':'Обычная','settings.on':'Вкл','settings.off':'Выкл','settings.slow':'Медленно','settings.default':'Средне','settings.fast':'Быстро','settings.faster':'Очень быстро',
    'ai.button':'AI','ai.name':'Ouclus','ai.subtitle':'Помощник этого урока','ai.hello':'Привет, я Ouclus. Спроси меня про ключ, S-Box, XOR, раунды, padding или текущий шаг.','ai.placeholder':'Спроси про AES...','ai.quick.step':'Текущий шаг','ai.quick.hint':'Подсказка','ai.quick.key':'Правило ключа','ai.thinking':'Разбираю шаг AES...','ai.system':'You are Claude inside an AES-256 teaching tool for students. Answer in Russian. Teach step by step, be concise, use the current AES stage context, explain calculations with small examples, never give unrelated content, and encourage the student to inspect the matrices and solve Student Checks themselves.',
    'ai.key.rule':'Для AES-256 здесь нужно ровно 32 символа. 32 байта x 8 бит = 256 бит.',
    'ai.fallback':'Claude proxy недоступен, поэтому я использовал встроенного AES-помощника.',
    'ai.xor':'0x{a} XOR 0x{b} = 0x{r}. Биты: {ab} xor {bb} = {rb}.',
    'ai.ascii':'ASCII значение: "{raw}" = decimal {n} = hex 0x{hex} = биты {bits}.',
    'ai.sbox':'S-Box[0x{byte}]: row {row}, column {col} дает 0x{out}.',
    'ai.key':'Для AES-256 ключ должен быть 32 байта. Этот сайт принимает 32 символа, затем каждый символ становится одним байтом ключа.',
    'ai.history':'AES был выбран NIST после открытого конкурса и стандартизирован в 2001 году. Победил алгоритм Rijndael.',
    'ai.text':'ASCII сопоставляет символ с числом. Например, A = decimal 65 = 0x41. AES шифрует байты, а не буквы напрямую.',
    'ai.byte':'Один байт содержит 8 бит. В hex один байт - это две цифры: 0x00 до 0xFF.',
    'ai.sbox.basic':'S-Box означает substitution. Например 0x53: row 5, column 3, таблица дает заменяющий байт.',
    'ai.xor.basic':'XOR сравнивает биты: одинаковые дают 0, разные дают 1. AddRoundKey - это state byte XOR round-key byte.',
    'ai.ecb':'ECB шифрует каждый блок независимо. Для обучения удобно, но в реальных системах чаще используют CBC, CTR или GCM.',
    'ai.gf':'GF(2^8) - конечное поле AES. MixColumns использует его, чтобы смешивать байты column в диапазоне 0x00-0xFF.',
    'ai.shift':'ShiftRows вращает строки влево: row 0 остается, row 1 на 1, row 2 на 2, row 3 на 3.',
    'ai.mix':'MixColumns смешивает каждый column, поэтому каждый output byte зависит от всех четырех байтов column.',
    'ai.padding':'PKCS#7 padding добавляет N байтов со значением N. Если не хватает 4 байта: 04 04 04 04.',
    'ai.round':'В AES-256 14 раундов: Round 0 AddRoundKey, rounds 1-13 полные шаги, round 14 без MixColumns.',
    'ai.result':'Ciphertext показывается только после Practice checks. Потом его можно сравнить на странице Result.',
    'ai.default':'Хороший вопрос. Я могу объяснить историю AES, ASCII, bytes, key size, XOR, S-Box, ShiftRows, MixColumns, padding, rounds, ECB mode или текущий шаг.',
    'student.check':'Проверка студента','student.correct':'Верно. Можно перейти к следующему шагу.','student.wrong':'Пока нет. Попытка {n}/3. {hint}','student.revealed':'Ответ показан после 3 ошибок. Прочитайте объяснение и продолжайте.','student.answer':'Ответ','student.explanation':'Объяснение','student.showAnswer':'Показать ответ',
    'score.points':'Очки','score.attempts':'Попытки','score.correctDelta':'+30 очков','score.incorrectDelta':'-10 очков','score.final':'Итоговый счет','score.totalAttempts':'Всего попыток','score.weakNone':'Сильное прохождение: по Student Checks слабое место не найдено.','score.weakDetail':'Слабое место: {skill}. На этот шаг ушло {attempts} попыток, повторите объяснение перед экзаменом.','score.skill.input':'текст в bytes','score.skill.key':'длина ключа AES-256','score.skill.xor':'AddRoundKey XOR','score.skill.sbox':'SubBytes S-Box','score.skill.shift':'ShiftRows','score.skill.mix':'MixColumns','score.skill.rounds':'структура раундов','score.skill.general':'основы AES',
    'alert.enter':'Сначала введите сообщение.','alert.short':'Для этого walkthrough используйте до 15 символов, чтобы один padded AES block был показан полностью.','alert.key':'Для AES-256 нужно ровно 32 символа ключа = 256 бит. Текущая длина: {n}/32.','alert.result.locked':'Сначала завершите AES Practice encryption. Result откроется после финального ciphertext шага.','alert.checks':'Ответьте на каждый Student Check, чтобы двигаться дальше.','alert.autoplay':'Auto play отключен в Practice. Решайте Student Check, чтобы открывать следующий AES step.','alert.encryptFirst':'Сначала выполните шифрование.',
    'result.stage':'Проверка результата','result.title':'Проверьте результат шифрования','result.desc':'На этом этапе можно проверить ciphertext из Practice и выполнить decrypt тем же AES-256 ключом.','result.latest':'Последний AES-256 output','result.sub':'Результат обновится после Practice encryption.','result.none':'Ciphertext пока нет. Сначала запустите Practice.','result.key':'Ключ','result.mode':'Режим','result.format':'Формат','result.external':'Не доверяешь мне - проверь там',
    'flow.title':'Один input -> одна полная схема AES раунда','flow.desc':'Введите сообщение и 32-символьный ключ. Перед каждым следующим шагом нужно вычислить небольшое AES значение.','flow.input':'Ваш input','flow.sub':'Введите один раз. Walkthrough покажет AES схему по шагам.','flow.note.html':'Encryption Key Size: <strong>256 Bits</strong> &nbsp;|&nbsp; Encryption Mode: <strong>ECB</strong> &nbsp;|&nbsp; Output format: <strong>HEX</strong>','flow.message':'Сообщение (max 15 chars)','flow.key':'Ключ (32 chars = 256-bit)','flow.encrypt':'Шифровать','flow.randomWord':'Случайное слово','flow.randomKey':'Случайный ключ','flow.clear':'Очистить','flow.empty.html':'Выполните задания выше, затем введите текст и нажмите <strong>Encrypt</strong>.','flow.cipher':'Ciphertext - AES-256 encrypted','flow.decrypted':'Decrypted:',
    'matrix.hover':'Наведите на byte, чтобы увидеть точное изменение.','matrix.before':'До','matrix.key':'Round Key','matrix.result':'Результат','matrix.xor':'XOR','matrix.equals':'=','matrix.byte':'Byte','matrix.prev':'Предыдущий byte','matrix.next':'Следующий byte','matrix.sboxHint':'S-Box подсказка: high nibble - row, low nibble - column.','matrix.sboxLookup':'S-Box lookup','matrix.input':'Input','matrix.output':'Output','matrix.high':'High nibble','matrix.low':'Low nibble','matrix.row':'Row','matrix.col':'Col','matrix.table':'S-Box table navigation','matrix.click':'Наведите или нажмите любой byte для расчета',
    'op.text':'Text','op.key':'Key','op.xor':'XOR','op.sbox':'S-Box','op.shift':'Shift','op.mix':'GF Mix','op.aes':'AES',
    'step.counter':'Шаг {n} из {total}',
    'step.input.badge':'Input','step.input.title':'Plaintext -> Bytes','step.input.why':'AES шифрует байты. Левая matrix показывает ваш текст, правая - byte values внутри AES state.','step.input.left':'Plaintext','step.input.out':'Plaintext bytes','step.input.prompt':'Опишите путь conversion до заполнения AES state matrix. Используйте слова character, ASCII и hex.','step.input.placeholder':'Character -> ...','step.input.hint':'Назовите три представления по порядку.','step.input.sample':'Character -> ASCII number -> hex byte -> state matrix.',
    'step.key.badge':'Key','step.key.title':'AES-256 Key Bytes','step.key.why':'AES-256 использует ровно 32 key bytes. Первые 16 bytes образуют Round Key 0.','step.key.left':'Key text','step.key.out':'Первые 16 key bytes','step.key.prompt':'Почему страница требует ровно 32 key characters для AES-256? Укажите оба числа.','step.key.placeholder':'32 characters because...','step.key.hint':'Каждый character становится одним byte, а 32 bytes дают 256 bits.','step.key.sample':'32 characters become 32 bytes, and 32 bytes x 8 bits = 256 bits.',
    'step.ark0.badge':'ARK 0','step.ark0.title':'Round 0 - AddRoundKey','step.ark0.why':'Перед Round 1 каждый state byte XOR-ится с Round Key 0.','step.ark0.out':'State после Round 0 key','step.ark0.detail':'XOR каждого byte - нажмите cell','step.ark0.prompt':'Вычислите AddRoundKey byte [{idx}] через before state и Round Key 0. Какой hex byte получится?','step.ark0.hint':'Используйте одинаковый index в state и round key, затем XOR их 8 bits.',
    'step.sub.badge':'SubBytes','step.sub.title':'Round 1 - SubBytes','step.sub.why':'Каждый byte заменяется через AES S-Box. Это substitution часть AES схемы.','step.sub.out':'После SubBytes','step.sub.detail':'S-Box lookup - нажмите byte','step.sub.prompt':'Используйте before matrix и S-Box, чтобы заменить byte [{idx}]. Какой output hex byte получится?','step.sub.hint':'Первая hex digit - row, вторая - column.',
    'step.shift.badge':'ShiftRows','step.shift.title':'Round 1 - ShiftRows','step.shift.why':'Rows вращаются влево на 0, 1, 2 и 3. Это перемещает bytes между columns перед MixColumns.','step.shift.out':'После ShiftRows','step.shift.detail':'Row movement - нажмите byte','step.shift.prompt':'В ShiftRows byte в row 1 начинается в before column {col}. В какой after column он перейдет?','step.shift.hint':'Row 1 вращается влево на один, значит column c переходит в c-1 с wraparound.',
    'step.mix.badge':'MixColumns','step.mix.title':'Round 1 - MixColumns','step.mix.why':'Каждый column смешивается в GF(2^8). Это diffusion часть AES схемы.','step.mix.out':'После MixColumns','step.mix.detail':'GF(2^8) calculation - нажмите byte','step.mix.prompt':'Для MixColumns output byte [{idx}] напишите row coefficient pattern без пробелов. Пример: 2311.','step.mix.hint':'Rows используют coefficient patterns 2311, 1231, 1123 и 3112.',
    'step.ark1.badge':'ARK 1','step.ark1.title':'Round 1 - AddRoundKey','step.ark1.why':'Round 1 заканчивается XOR mixed state с Round Key 1.','step.ark1.out':'После Round Key 1','step.ark1.detail':'XOR с round key - нажмите byte','step.ark1.prompt':'Вычислите Round 1 AddRoundKey byte [{idx}] из mixed state и Round Key 1. Какой hex byte получится?','step.ark1.hint':'Используйте mixed-state byte и Round Key 1 byte с тем же index.',
    'step.scheme.badge':'Scheme','step.scheme.title':'AES схема продолжается','step.scheme.why':'AES-256 повторяет тот же four-step block для Rounds 2-13, затем использует final Round 14 без MixColumns.','step.scheme.prompt':'Напишите, какой step пропускает final AES round.','step.scheme.placeholder':'The final round skips...','step.scheme.hint':'В final round нет MixColumns.','step.scheme.sample':'The final round skips MixColumns.',
    'step.output.badge':'Output','step.output.title':'Final Ciphertext','step.output.why':'Настоящий AES-256 результат вычисляется полным алгоритмом. Matrix читается как одна continuous ciphertext line.','step.output.out':'Ciphertext bytes',
    'explain.input':'AES не шифрует буквы напрямую. Сначала каждый character превращается в ASCII number. Это число записывается как двухзначный hexadecimal byte. 16 bytes заполняют AES state matrix, а пустые cells заполняют padding bytes.',
    'explain.key':'AES-256 означает, что key имеет 256 bits. На этой странице один character равен одному byte, поэтому 32 characters становятся 32 bytes. Каждый byte содержит 8 bits: 32 x 8 = 256 bits.',
    'explain.ark':'AddRoundKey - это byte-by-byte XOR. Выберите одинаковый index в state matrix и round-key matrix. Переведите оба bytes в bits, сравните каждый bit: 0 для одинаковых, 1 для разных. Затем переведите результат обратно в hex.',
    'explain.sub':'SubBytes использует S-Box table. Разделите input byte на две hex digits. Первая digit выбирает row, вторая digit выбирает column. Cell на пересечении дает replacement byte.',
    'explain.shift':'ShiftRows перемещает bytes внутри каждой row. Row 0 не меняется, row 1 влево на 1, row 2 на 2, row 3 на 3. Значения заворачиваются в конец этой же row.',
    'explain.mix':'MixColumns использует fixed coefficient row. Для каждого output byte четыре column bytes умножаются на coefficients в GF(2^8), затем четыре products XOR-ятся.',
    'explain.scheme':'AES-256 много раз повторяет full round structure. Final round все еще содержит SubBytes, ShiftRows и AddRoundKey, но пропускает MixColumns.',
    'explain.output':'Ciphertext - это final AES state, записанный как continuous hexadecimal string. Без того же 256-bit key его обратное восстановление должно быть вычислительно infeasible.',
    'instruction.default':'Нажимайте Next, чтобы пройти AES course.','instruction.title':'Инструкция','instruction.scheme':'Как вычислять оставшийся AES path:\nRounds 2-13 повторяют SubBytes, ShiftRows, MixColumns, AddRoundKey.\nПример: после Round 1 зеленый маркер проходит этот four-step block еще 12 раз. Round 14 пропускает MixColumns.','instruction.output':'Как сформировать ciphertext:\nПрочитайте final 4x4 state как одну continuous hexadecimal line.\nПример: возьмите каждый byte в display order, уберите spaces и соедините в HEX string.','instruction.input':'Как вычислять plaintext bytes:\nПереведите каждый character в ASCII, затем в hex, затем поставьте в state.\nПример: "{ch}" -> ASCII {dec} -> hex {hex}.','instruction.key':'Как вычислять key bytes:\nКаждый key character становится одним byte. AES-256 требует 32 key characters, потому что 32 bytes x 8 bits = 256 bits.\nПример: K[0] -> {hex}.','instruction.ark':'Как вычислять AddRoundKey:\nИспользуйте один и тот же byte index: state byte XOR round-key byte = result.\nПример [{idx}]: {before} XOR {key} = {after}. Одинаковые bits дают 0, разные bits дают 1.','instruction.sub':'Как вычислять SubBytes:\nИспользуйте S-Box. Первая hex digit - row, вторая - column.\nПример [{idx}]: input {byte}, row {row}, column {col}, output {after}.','instruction.shift':'Как вычислять ShiftRows:\nВращайте каждую row влево на номер этой row.\nПример: row {row} движется влево на {row}, поэтому before [{src}] попадает в after [{dst}].','instruction.mix':'Как вычислять MixColumns:\nКаждый output byte использует все четыре bytes в same column с GF(2^8) multiplication.\nПример: column {col} берет {bytes} и дает output [{idx}] = {after}.'
  }
};
Object.assign(I18N.us,{
  'score.success':'Success','score.max':'Max points','score.mistakes':'Mistakes','score.correct':'Correct checks',
  'calc.title':'AES Calculator','calc.standard':'Standard','calc.ready':'Ready for AES byte math','calc.history':'History','calc.noHistory':'No calculations yet.',
  'calc.info':'Text: {plain} chars | Block: 16 bytes | Key: {key}/32 chars = {bits} bits',
  'calc.xor':'XOR Calculator','calc.xorA':'Matrix / bytes A','calc.xorB':'Matrix / bytes B','calc.xorRun':'XOR bytes','calc.xorEmpty':'Enter hex bytes like 5C or 5C 16 A3.','calc.xorError':'Use valid hex bytes only.'
});
Object.assign(I18N.kz,{
  'score.success':'Жетістік','score.max':'Макс. ұпай','score.mistakes':'Қате','score.correct':'Дұрыс тексеріс',
  'calc.title':'AES калькулятор','calc.standard':'Стандарт','calc.ready':'AES byte math дайын','calc.history':'Тарих','calc.noHistory':'Әзірге есеп жоқ.',
  'calc.info':'Мәтін: {plain} таңба | Block: 16 byte | Кілт: {key}/32 таңба = {bits} bit',
  'calc.xor':'XOR калькулятор','calc.xorA':'1-матрица / bytes','calc.xorB':'2-матрица / bytes','calc.xorRun':'XOR есептеу','calc.xorEmpty':'5C немесе 5C 16 A3 сияқты hex byte енгізіңіз.','calc.xorError':'Тек дұрыс hex byte қолданыңыз.'
});
Object.assign(I18N.ru,{
  'score.success':'Успех','score.max':'Макс. очки','score.mistakes':'Ошибки','score.correct':'Верные проверки',
  'calc.title':'AES калькулятор','calc.standard':'Стандартный','calc.ready':'Готов к AES byte math','calc.history':'История','calc.noHistory':'Вычислений пока нет.',
  'calc.info':'Текст: {plain} символов | Блок: 16 bytes | Ключ: {key}/32 символов = {bits} bits',
  'calc.xor':'XOR калькулятор','calc.xorA':'1-матрица / bytes','calc.xorB':'2-матрица / bytes','calc.xorRun':'Вычислить XOR','calc.xorEmpty':'Введите hex bytes, например 5C или 5C 16 A3.','calc.xorError':'Используйте только корректные hex bytes.'
});
Object.assign(I18N.us,{
  'about.stage':'Theory 1 - AES-256','about.title':'What is AES-256?','about.desc':'AES-256 is the strongest variant of the Advanced Encryption Standard, standardised by NIST in 2001. It uses a 256-bit key and 14 rounds. Used in government, military, banking, and every HTTPS connection worldwide.',
  'about.c1.l':'Block cipher','about.c1.t':'128-bit blocks','about.c1.p':'Data is arranged into a 4x4 grid of bytes called the <strong>state matrix</strong>. AES transforms this state through 14 rounds of operations.',
  'about.c2.l':'256-bit key','about.c2.t':'2^256 keys','about.c2.p':'More possibilities than atoms in the observable universe. Brute force is impossible even for all computers on Earth combined.',
  'about.c3.l':'14 rounds','about.c3.t':'Nr = Nk + 6','about.c3.p':'AES-256 has Nk=8 key words, so rounds = 8+6 = <strong>14</strong>. Each round applies 4 different operations with a unique round key.',
  'about.c4.l':'Symmetric','about.c4.t':'Same key both ways','about.c4.p':'The exact same 256-bit key encrypts and decrypts. AES-256 provides 128-bit post-quantum security against Grover algorithm.',
  'about.table.property':'Property','about.table.key':'Key size','about.table.rounds':'Rounds','about.table.roundkeys':'Round keys','about.table.space':'Key space','about.table.quantum':'Post-quantum','about.note.html':'<strong>Why 256 bits?</strong> AES-128 is already unbreakable today. AES-256 adds an extra 128-bit safety margin for future quantum computers.',
  'key.stage':'Theory 2 - Key Expansion','key.title':'Key Schedule: 32 bytes -> 15 round keys','key.desc':'AES never uses the same key twice. Your 32-byte secret expands into 15 unique round keys. Click each stage.','key.explain.html':'<strong>Original Key (256 bits):</strong> Your 32-byte secret split into 8 words W[0]-W[7]. These form Round Key 0 directly.',
  'sbox.stage':'Theory 3 - S-Box','sbox.title':'AES S-Box - Full Lookup Table','sbox.desc':'SubBytes replaces every byte using this 16x16 table. High nibble = row, low nibble = column. Left click marks the intersection; right click shows row and column near the mouse.','sbox.note.html':'<strong>Example:</strong> Byte 0x53 -> row 5, col 3 -> S-Box[5][3] = <strong>0xED</strong>.',
  'round.stage':'Theory 4 - Round Structure','round.title':'AES-256: 14 Rounds - Why and How','round.desc':'Formula: Rounds = Key words + 6 = 8 + 6 = 14. Each round mixes the data further.','round.all':'All 14 rounds','round.animate':'Animate','round.why.html':'<strong>Why 14?</strong> Rule: Rounds = Key words + 6 = 8+6 = <strong>14</strong>. More key bits -> more rounds -> harder to reverse.',
  'practice.stage':'Practice - Solve It Yourself','practice.title':'Interactive Tasks','practice.desc':'Complete these tasks before watching the full encryption. You solve the first few bytes manually, then the computer finishes the rest.',
  'practice.t1.label':'Task 1 of 4 - ASCII Conversion','practice.t1.q':'Convert the first 3 characters of "Hello" to hexadecimal','practice.t1.h':'AES works on bytes, not letters. Every character has an ASCII code. Convert it to hex.',
  'practice.t2.label':'Task 2 of 4 - XOR Operation','practice.t2.q':'Calculate XOR - the core of AddRoundKey','practice.t2.h':'XOR compares bits one by one: same bits give 0, different bits give 1.',
  'practice.t3.label':'Task 3 of 4 - S-Box SubBytes','practice.t3.q':'Look up two bytes in the S-Box','practice.t3.h':'Split the byte into two hex digits: first digit is row, second digit is column.',
  'practice.t4.label':'Task 4 of 4 - ShiftRows','practice.t4.q':'Apply ShiftRows: rotate Row 1 left by 1 position','practice.t4.h':'ShiftRows rotates each row cyclically left. Row 0 stays, row 1 shifts by 1, row 2 by 2, row 3 by 3.',
  'practice.done':'All 4 tasks done? Now use your own input in Practice. The site will teach one complete AES round scheme.',
  'team.stage':'Narxoz University - Final Project','team.title':'Project Team','team.desc':'Topic 1: AES-256 Encryption + Key Generation. Final Examination - Cryptographic Primitives, 2025-2026.','team.acad.html':'<strong>Academic Declaration:</strong> Created independently by students of Narxoz University for the Final Examination, Cryptographic Primitives course, 2025-2026. AES-256 follows NIST FIPS-197.','footer.html':'<strong>AES-256 Learning Platform</strong><br>Narxoz University . Cryptographic Primitives . 2025-2026<br><span style="font-size:.64rem;opacity:.36;display:block;margin-top:3px">NIST FIPS-197 . Topic 1: AES-256 + Key Generation</span>'
});
Object.assign(I18N.kz,{
  'about.stage':'Теория 1 - AES-256','about.title':'AES-256 деген не?','about.desc':'AES-256 - Advanced Encryption Standard алгоритмінің ең күшті нұсқасы. Ол 256-bit кілт және 14 раунд қолданады.',
  'about.c1.l':'Block cipher','about.c1.t':'128-bit блоктар','about.c1.p':'Дерек byte-тардан тұратын 4x4 торға, яғни <strong>state matrix</strong> ішіне орналасады.',
  'about.c2.l':'256-bit кілт','about.c2.t':'2^256 кілт','about.c2.p':'Мүмкін кілт саны өте көп, brute force арқылы бұзу іс жүзінде мүмкін емес.',
  'about.c3.l':'14 раунд','about.c3.t':'Nr = Nk + 6','about.c3.p':'AES-256 үшін Nk=8, сондықтан раунд саны 8+6 = <strong>14</strong>.',
  'about.c4.l':'Symmetric','about.c4.t':'Бір кілт екі бағытта','about.c4.p':'Бір 256-bit кілт шифрлауға да, decrypt жасауға да қолданылады.',
  'about.table.property':'Қасиет','about.table.key':'Кілт өлшемі','about.table.rounds':'Раундтар','about.table.roundkeys':'Раунд кілттері','about.table.space':'Кілт кеңістігі','about.table.quantum':'Post-quantum','about.note.html':'<strong>Неге 256 bit?</strong> AES-256 болашақ quantum шабуылдарына қарсы қосымша қауіпсіздік қорын береді.',
  'key.stage':'Теория 2 - Key Expansion','key.title':'Key Schedule: 32 byte -> 15 round key','key.desc':'AES бір кілтті тура қайталамайды. 32-byte құпия 15 бөлек round key болып кеңейеді.','key.explain.html':'<strong>Original Key (256 bits):</strong> 32-byte құпия W[0]-W[7] сөздеріне бөлінеді.',
  'sbox.stage':'Теория 3 - S-Box','sbox.title':'AES S-Box - толық lookup table','sbox.desc':'SubBytes әр byte мәнін 16x16 кесте арқылы ауыстырады. Сол жақ click intersection қояды, оң жақ click row және column көрсетеді.','sbox.note.html':'<strong>Мысал:</strong> Byte 0x53 -> row 5, col 3 -> S-Box[5][3] = <strong>0xED</strong>.',
  'round.stage':'Теория 4 - Раунд құрылымы','round.title':'AES-256: 14 раунд - неге және қалай','round.desc':'Формула: Rounds = Key words + 6 = 8 + 6 = 14. Әр раунд деректі көбірек араластырады.','round.all':'Барлық 14 раунд','round.animate':'Анимация','round.why.html':'<strong>Неге 14?</strong> Ереже: Rounds = Key words + 6 = 8+6 = <strong>14</strong>.',
  'practice.stage':'Практика - өзіңіз шешіңіз','practice.title':'Интерактивті тапсырмалар','practice.desc':'Толық шифрлауды көрмей тұрып осы тапсырмаларды орындаңыз. Алдымен бірнеше byte-ты өзіңіз есептейсіз.',
  'practice.t1.label':'1/4 тапсырма - ASCII conversion','practice.t1.q':'"Hello" сөзінің алғашқы 3 таңбасын hexadecimal түріне ауыстырыңыз','practice.t1.h':'AES әріптермен емес, byte-пен жұмыс істейді. Әр таңбаның ASCII коды бар.',
  'practice.t2.label':'2/4 тапсырма - XOR operation','practice.t2.q':'XOR есептеңіз - AddRoundKey негізі','practice.t2.h':'XOR bit-терді салыстырады: бірдей болса 0, әртүрлі болса 1.',
  'practice.t3.label':'3/4 тапсырма - S-Box SubBytes','practice.t3.q':'S-Box ішінен екі byte табыңыз','practice.t3.h':'Byte екі hex digit-ке бөлінеді: біріншісі row, екіншісі column.',
  'practice.t4.label':'4/4 тапсырма - ShiftRows','practice.t4.q':'ShiftRows орындаңыз: Row 1 мәнін 1 орынға солға жылжытыңыз','practice.t4.h':'ShiftRows әр row-ды циклдік түрде солға жылжытады.',
  'practice.done':'4 тапсырма бітті ме? Енді Practice ішінде өз input мәніңізді қолданыңыз.',
  'team.stage':'Narxoz University - Final Project','team.title':'Жоба тобы','team.desc':'Topic 1: AES-256 Encryption + Key Generation. Final Examination - Cryptographic Primitives, 2025-2026.','team.acad.html':'<strong>Academic Declaration:</strong> Narxoz University студенттері Final Examination үшін өздері жасаған. AES-256 NIST FIPS-197 стандартына сүйенеді.','footer.html':'<strong>AES-256 Learning Platform</strong><br>Narxoz University . Cryptographic Primitives . 2025-2026<br><span style="font-size:.64rem;opacity:.36;display:block;margin-top:3px">NIST FIPS-197 . Topic 1: AES-256 + Key Generation</span>'
});
Object.assign(I18N.ru,{
  'about.stage':'Теория 1 - AES-256','about.title':'Что такое AES-256?','about.desc':'AES-256 - самый сильный вариант Advanced Encryption Standard. Он использует 256-bit ключ и 14 раундов.',
  'about.c1.l':'Block cipher','about.c1.t':'128-bit блоки','about.c1.p':'Данные помещаются в сетку 4x4 из bytes, которая называется <strong>state matrix</strong>.',
  'about.c2.l':'256-bit ключ','about.c2.t':'2^256 ключей','about.c2.p':'Возможных ключей настолько много, что brute force практически невозможен.',
  'about.c3.l':'14 раундов','about.c3.t':'Nr = Nk + 6','about.c3.p':'Для AES-256 Nk=8, поэтому число раундов равно 8+6 = <strong>14</strong>.',
  'about.c4.l':'Symmetric','about.c4.t':'Один ключ в обе стороны','about.c4.p':'Один и тот же 256-bit ключ используется для encryption и decrypt.',
  'about.table.property':'Свойство','about.table.key':'Размер ключа','about.table.rounds':'Раунды','about.table.roundkeys':'Раундовые ключи','about.table.space':'Пространство ключей','about.table.quantum':'Post-quantum','about.note.html':'<strong>Почему 256 bit?</strong> AES-256 дает дополнительный запас безопасности против будущих quantum атак.',
  'key.stage':'Теория 2 - Key Expansion','key.title':'Key Schedule: 32 bytes -> 15 round keys','key.desc':'AES не использует один и тот же ключ напрямую. 32-byte секрет расширяется в 15 разных round keys.','key.explain.html':'<strong>Original Key (256 bits):</strong> 32-byte секрет делится на слова W[0]-W[7].',
  'sbox.stage':'Теория 3 - S-Box','sbox.title':'AES S-Box - полная lookup table','sbox.desc':'SubBytes заменяет каждый byte через таблицу 16x16. Левый click ставит intersection, правый click показывает row и column.','sbox.note.html':'<strong>Пример:</strong> Byte 0x53 -> row 5, col 3 -> S-Box[5][3] = <strong>0xED</strong>.',
  'round.stage':'Теория 4 - Структура раундов','round.title':'AES-256: 14 раундов - почему и как','round.desc':'Формула: Rounds = Key words + 6 = 8 + 6 = 14. Каждый раунд сильнее перемешивает данные.','round.all':'Все 14 раундов','round.animate':'Анимировать','round.why.html':'<strong>Почему 14?</strong> Правило: Rounds = Key words + 6 = 8+6 = <strong>14</strong>.',
  'practice.stage':'Практика - решите сами','practice.title':'Интерактивные задания','practice.desc':'Выполните задания перед полным шифрованием. Сначала вы вручную считаете несколько bytes.',
  'practice.t1.label':'Задание 1 из 4 - ASCII conversion','practice.t1.q':'Переведите первые 3 символа "Hello" в hexadecimal','practice.t1.h':'AES работает с bytes, а не с буквами. У каждого символа есть ASCII код.',
  'practice.t2.label':'Задание 2 из 4 - XOR operation','practice.t2.q':'Вычислите XOR - основу AddRoundKey','practice.t2.h':'XOR сравнивает bits: одинаковые дают 0, разные дают 1.',
  'practice.t3.label':'Задание 3 из 4 - S-Box SubBytes','practice.t3.q':'Найдите два bytes в S-Box','practice.t3.h':'Разделите byte на две hex digits: первая дает row, вторая column.',
  'practice.t4.label':'Задание 4 из 4 - ShiftRows','practice.t4.q':'Выполните ShiftRows: сдвиньте Row 1 влево на 1 позицию','practice.t4.h':'ShiftRows циклически сдвигает каждую row влево.',
  'practice.done':'Все 4 задания выполнены? Теперь используйте свой input в Practice.',
  'team.stage':'Narxoz University - Final Project','team.title':'Команда проекта','team.desc':'Topic 1: AES-256 Encryption + Key Generation. Final Examination - Cryptographic Primitives, 2025-2026.','team.acad.html':'<strong>Academic Declaration:</strong> Создано студентами Narxoz University для Final Examination. AES-256 следует NIST FIPS-197.','footer.html':'<strong>AES-256 Learning Platform</strong><br>Narxoz University . Cryptographic Primitives . 2025-2026<br><span style="font-size:.64rem;opacity:.36;display:block;margin-top:3px">NIST FIPS-197 . Topic 1: AES-256 + Key Generation</span>'
});
const KEY_SCHEDULE_TEXT={
  us:kst,
  kz:[
    '<strong>Original Key (256 bits = 32 bytes):</strong> 32-byte құпия W[0]-W[7] болып бөлінеді. Олар Round Key 0 жасайды.',
    '<strong>W[0..7] - Round Key 0:</strong> Алғашқы 8 word бастапқы кілттен алынады және plaintext-пен XOR жасалады.',
    '<strong>RotWord:</strong> Соңғы word 1 byte солға айналады: [a0,a1,a2,a3]->[a1,a2,a3,a0].',
    '<strong>SubWord:</strong> RotWord ішіндегі 4 byte AES S-Box арқылы ауысады. Бұл non-linearity береді.',
    '<strong>XOR with Rcon:</strong> Бірінші byte round constant-пен XOR жасалады, сондықтан key schedule әр раундта өзгеше болады.',
    '<strong>Extra SubWord (тек AES-256):</strong> Word index mod 8 = 4 болғанда қосымша SubWord қолданылады.',
    '<strong>W[8..15] - Round Key 1:</strong> W[8]=W[0] XOR temp, W[9]=W[1] XOR W[8] формуласы жалғасады.',
    '<strong>W[56..59] - Round Key 14:</strong> Соңғы round key. Барлығы 60 word және 15 round key дайын болады.'
  ],
  ru:[
    '<strong>Original Key (256 bits = 32 bytes):</strong> 32-byte секрет делится на W[0]-W[7]. Они сразу образуют Round Key 0.',
    '<strong>W[0..7] - Round Key 0:</strong> Первые 8 words берутся из исходного ключа и XOR-ятся с plaintext.',
    '<strong>RotWord:</strong> Последнее word вращается влево на 1 byte: [a0,a1,a2,a3]->[a1,a2,a3,a0].',
    '<strong>SubWord:</strong> 4 bytes проходят через AES S-Box. Это добавляет non-linearity.',
    '<strong>XOR with Rcon:</strong> Первый byte XOR-ится с round constant, чтобы ключи раундов отличались.',
    '<strong>Extra SubWord (только AES-256):</strong> Когда word index mod 8 = 4, применяется дополнительный SubWord.',
    '<strong>W[8..15] - Round Key 1:</strong> W[8]=W[0] XOR temp, W[9]=W[1] XOR W[8], и процесс продолжается.',
    '<strong>W[56..59] - Round Key 14:</strong> Финальный round key. Всего получается 60 words и 15 round keys.'
  ]
};
Object.assign(I18N.us,{
  'practice.ascii':'Show ASCII Table (hint)','practice.ascii.title':'ASCII Table - Character to Number','practice.ascii.desc':'Each character = decimal number = hex. Example: H = 72 = 0x48',
  'practice.t1.ok':'Correct! H=0x48, e=0x65, l=0x6C. AES stores every character as its hex byte.','practice.t1.no':'Not quite. H = ASCII 72. 72 in hex is 0x48. Use the table above and look up each character.',
  'practice.t2.ok':'Correct! 0x48 XOR 0x49 = 0x01, and 0x65 XOR 0xA0 = 0xC5. XOR also undoes itself.','practice.t2.no':'Not quite. For each bit pair: same=0, different=1. 01001000 XOR 01001001 = 00000001.',
  'practice.t3.ok':'Correct! S-Box[1][9] = 0xD4 and S-Box[A][0] = 0xE0.','practice.t3.no':'Not quite. Find row 1x and column x9 in the S-Box table. That cell is the answer for 0x19.',
  'practice.t4.ok':'Correct! [27 BF B4 41] shifted left by 1 becomes [BF B4 41 27].','practice.t4.no':'Not quite. Shift left by 1 means [a b c d] -> [b c d a].'
});
Object.assign(I18N.kz,{
  'practice.ascii':'ASCII кестесін көрсету (көмек)','practice.ascii.title':'ASCII кесте - таңбадан санға','practice.ascii.desc':'Әр таңба = decimal сан = hex. Мысал: H = 72 = 0x48',
  'practice.t1.ok':'Дұрыс! H=0x48, e=0x65, l=0x6C. AES әр таңбаны hex byte ретінде сақтайды.','practice.t1.no':'Әлі дұрыс емес. H = ASCII 72, ал 72 hex түрінде 0x48. Кестені қолданыңыз.',
  'practice.t2.ok':'Дұрыс! 0x48 XOR 0x49 = 0x01, ал 0x65 XOR 0xA0 = 0xC5. XOR өзін қайта қайтарады.','practice.t2.no':'Әлі дұрыс емес. Бірдей bit -> 0, әртүрлі bit -> 1. 01001000 XOR 01001001 = 00000001.',
  'practice.t3.ok':'Дұрыс! S-Box[1][9] = 0xD4 және S-Box[A][0] = 0xE0.','practice.t3.no':'Әлі дұрыс емес. S-Box кестесінен row 1x және column x9 табыңыз.',
  'practice.t4.ok':'Дұрыс! [27 BF B4 41] солға 1 орын жылжыса [BF B4 41 27] болады.','practice.t4.no':'Әлі дұрыс емес. Солға 1 shift: [a b c d] -> [b c d a].'
});
Object.assign(I18N.ru,{
  'practice.ascii':'Показать ASCII таблицу (подсказка)','practice.ascii.title':'ASCII таблица - символ в число','practice.ascii.desc':'Каждый символ = decimal число = hex. Пример: H = 72 = 0x48',
  'practice.t1.ok':'Верно! H=0x48, e=0x65, l=0x6C. AES хранит каждый символ как hex byte.','practice.t1.no':'Пока нет. H = ASCII 72, а 72 в hex это 0x48. Используйте таблицу.',
  'practice.t2.ok':'Верно! 0x48 XOR 0x49 = 0x01, а 0x65 XOR 0xA0 = 0xC5. XOR также сам себя отменяет.','practice.t2.no':'Пока нет. Одинаковые bits дают 0, разные bits дают 1. 01001000 XOR 01001001 = 00000001.',
  'practice.t3.ok':'Верно! S-Box[1][9] = 0xD4 и S-Box[A][0] = 0xE0.','practice.t3.no':'Пока нет. Найдите row 1x и column x9 в таблице S-Box.',
  'practice.t4.ok':'Верно! [27 BF B4 41] со сдвигом влево на 1 становится [BF B4 41 27].','practice.t4.no':'Пока нет. Сдвиг влево на 1: [a b c d] -> [b c d a].'
});
const AES_SIDE_CARDS={
  interesting:[
    'AES is not hiding letters one by one. One changed bit spreads through the state until the ciphertext looks unrelated to the message.',
    'The AES S-Box was built from finite-field math, not chosen randomly. It is designed to make algebraic attacks hard.',
    'AES always works on a 16-byte block. Even a short word is padded before encryption.',
    'Changing one key character should change many ciphertext bytes. This is called the avalanche effect.',
    'AES became a U.S. federal standard in 2001 after an open international competition.',
    'SubBytes gives confusion, while ShiftRows and MixColumns help diffusion.',
    'The final AES round skips MixColumns, but still uses SubBytes, ShiftRows, and AddRoundKey.',
    'XOR is its own inverse: if A xor K = B, then B xor K = A.',
    'The same plaintext encrypted with the same key in ECB gives the same ciphertext block.',
    'AES-256 has 14 rounds because Nk + 6 = 8 + 6.'
  ],
  theory:[
    'AES-256 uses a 256-bit key, which means exactly 32 bytes in this site.',
    'The state matrix is 4 rows by 4 columns. Each cell is one byte.',
    'Round 0 only applies AddRoundKey before the normal rounds begin.',
    'Rounds 1-13 use SubBytes, ShiftRows, MixColumns, and AddRoundKey.',
    'Round 14 is the final AES-256 round and skips MixColumns.',
    'PKCS#7 padding fills the last block. If 5 bytes are missing, each padding byte is 0x05.',
    'SubBytes replaces each byte using the S-Box table.',
    'ShiftRows rotates row 0 by 0, row 1 by 1, row 2 by 2, and row 3 by 3.',
    'MixColumns treats each column as finite-field values and mixes all four bytes.',
    'AddRoundKey XORs each state byte with the matching round-key byte.'
  ],
  hint:[
    'For manual checks, track one byte: text -> hex, XOR with key byte, S-Box substitution, row shift, then column mix.',
    'When converting text to hex, first find the ASCII decimal value, then convert decimal to base 16.',
    'For XOR, write both bytes as 8 bits. Same bits give 0, different bits give 1.',
    'For S-Box lookup, the first hex digit is the row and the second hex digit is the column.',
    'For ShiftRows, draw the 4x4 state as rows before moving values.',
    'For MixColumns, click the byte in the practice grid to see the GF multiplication detail.',
    'If the key check fails, count characters. AES-256 here needs exactly 32.',
    'If Result is locked, finish every Student Check in Practice first.',
    'Use AES Map when you forget where the current step sits in the full scheme.',
    'For the final round question, remember: no MixColumns.'
  ]
};

const COURSE_STAGE_KEYS={
  main:['stage.main','stage.main.note'],
  theory:['stage.theory','stage.theory.note'],
  tasks:['stage.tasks','stage.tasks.note'],
  encrypt:['stage.encrypt','stage.encrypt.note'],
  result:['stage.result','stage.result.note'],
  team:['stage.team','stage.team.note']
};

const STATIC_I18N=[
  ['.hbrand','brand.html','html'],
  ['header .hlinks a[href="#about"]','nav.theory'],
  ['header .hlinks a[href="#prac-sec"]','nav.practice'],
  ['header .hlinks a[href="#flow-sec"]','nav.encrypt'],
  ['header .hlinks a[href="#team"]','nav.team'],
  ['.h-sup','hero.sup'],
  ['.hero h1','hero.title.html','html'],
  ['.hero-d','hero.desc'],
  ['.hcta .btn-p','hero.start'],
  ['.hcta .btn-o','hero.read'],
  ['#flow-sec .sh','flow.title'],
  ['#flow-sec .sd','flow.desc'],
  ['#flow-sec .fi-title','flow.input'],
  ['#flow-sec .fi-sub','flow.sub'],
  ['#flow-sec .tool-note','flow.note.html','html'],
  ['#flow-sec .fg:nth-child(1) label','flow.message'],
  ['#flow-sec .fg:nth-child(2) label','flow.key'],
  ['#flow-sec .input-actions .btn-p','flow.encrypt'],
  ['#flow-sec .input-actions .btn-o:nth-child(2)','flow.randomWord'],
  ['#flow-sec .input-actions .btn-o:nth-child(3)','flow.randomKey'],
  ['#flow-sec .input-actions .btn-o:nth-child(4)','flow.clear'],
  ['#out-blk .out-lbl','flow.cipher'],
  ['#result-sec .stag','result.stage'],
  ['#result-sec .sh','result.title'],
  ['#result-sec .sd','result.desc'],
  ['#result-sec .fi-title','result.latest'],
  ['#result-sec .fi-sub','result.sub'],
  ['#result-sec .result-meta div:nth-child(1) span','result.key'],
  ['#result-sec .result-meta div:nth-child(2) span','result.mode'],
  ['#result-sec .result-meta div:nth-child(3) span','result.format'],
  ['#result-back-btn','btn.backPractice'],
  ['#result-decrypt-btn','btn.decrypt'],
  ['#result-external-link','result.external'],
  ['#result-map-btn','btn.map']
];
STATIC_I18N.push(
  ['#about .stag','about.stage'],['#about .sh','about.title'],['#about .sd','about.desc'],
  ['#about .ac:nth-child(1) .aclbl','about.c1.l'],['#about .ac:nth-child(1) h3','about.c1.t'],['#about .ac:nth-child(1) p','about.c1.p','html'],
  ['#about .ac:nth-child(2) .aclbl','about.c2.l'],['#about .ac:nth-child(2) h3','about.c2.t'],['#about .ac:nth-child(2) p','about.c2.p','html'],
  ['#about .ac:nth-child(3) .aclbl','about.c3.l'],['#about .ac:nth-child(3) h3','about.c3.t'],['#about .ac:nth-child(3) p','about.c3.p','html'],
  ['#about .ac:nth-child(4) .aclbl','about.c4.l'],['#about .ac:nth-child(4) h3','about.c4.t'],['#about .ac:nth-child(4) p','about.c4.p','html'],
  ['#about .ctbl thead th:nth-child(1)','about.table.property'],['#about .ctbl tbody tr:nth-child(1) td:nth-child(1)','about.table.key'],['#about .ctbl tbody tr:nth-child(2) td:nth-child(1)','about.table.rounds'],['#about .ctbl tbody tr:nth-child(3) td:nth-child(1)','about.table.roundkeys'],['#about .ctbl tbody tr:nth-child(4) td:nth-child(1)','about.table.space'],['#about .ctbl tbody tr:nth-child(5) td:nth-child(1)','about.table.quantum'],['#about .ibox','about.note.html','html'],
  ['#keygen .stag','key.stage'],['#keygen .sh','key.title'],['#keygen .sd','key.desc'],['#ksex','key.explain.html','html'],
  ['#sbox-sec .stag','sbox.stage'],['#sbox-sec .sh','sbox.title'],['#sbox-sec .sd','sbox.desc'],['#sbox-sec .ibox','sbox.note.html','html'],
  ['#rnd-sec .stag','round.stage'],['#rnd-sec .sh','round.title'],['#rnd-sec .sd','round.desc'],['#rnd-sec .rdbig > div:first-child','round.all'],['#rnd-sec .rdbig button','round.animate'],['#rnd-sec .rdbig > div:last-child','round.why.html','html'],
  ['#prac-sec .stag','practice.stage'],['#prac-sec .sh','practice.title'],['#prac-sec .sd','practice.desc'],
  ['#t1 .task-q','practice.t1.q'],['#t1 .task-hint','practice.t1.h'],['#t2 .task-q','practice.t2.q'],['#t2 .task-hint','practice.t2.h'],['#t3 .task-q','practice.t3.q'],['#t3 .task-hint','practice.t3.h'],['#t4 .task-q','practice.t4.q'],['#t4 .task-hint','practice.t4.h'],
  ['#ah1','practice.ascii'],['#ap1 h4','practice.ascii.title'],['#ap1 p','practice.ascii.desc'],
  ['#t1ok','practice.t1.ok'],['#t1no','practice.t1.no'],['#t2ok','practice.t2.ok'],['#t2no','practice.t2.no'],['#t3ok','practice.t3.ok'],['#t3no','practice.t3.no'],['#t4ok','practice.t4.ok'],['#t4no','practice.t4.no'],
  ['#prac-sec .chk-btn','btn.check'],['#prac-sec .rvl-btn','student.showAnswer'],['#prac-sec > .sec > .ibox','practice.done'],
  ['#team .stag','team.stage'],['#team .sh','team.title'],['#team .sd','team.desc'],['#team .acad','team.acad.html','html'],['footer','footer.html','html']
);
const STATIC_ATTR_I18N=[
  ['#t1','data-label','practice.t1.label'],['#t2','data-label','practice.t2.label'],['#t3','data-label','practice.t3.label'],['#t4','data-label','practice.t4.label']
];

function t(key,vars={}){
  const dict=I18N[siteSettings.lang]||I18N.us;
  const text=dict[key]!==undefined?dict[key]:(I18N.us[key]!==undefined?I18N.us[key]:key);
  return String(text).replace(/\{(\w+)\}/g,(_,name)=>vars[name]!==undefined?vars[name]:'');
}
function applyStaticTranslations(){
  STATIC_I18N.forEach(([sel,key,mode])=>{
    document.querySelectorAll(sel).forEach(el=>{
      if(mode==='html')el.innerHTML=t(key);
      else el.textContent=t(key);
    });
  });
  STATIC_ATTR_I18N.forEach(([sel,attr,key])=>{
    document.querySelectorAll(sel).forEach(el=>el.setAttribute(attr,t(key)));
  });
  const pLabel=document.querySelector('#flow-sec .fg:nth-child(1) label');
  const kLabel=document.querySelector('#flow-sec .fg:nth-child(2) label');
  if(pLabel)pLabel.textContent=t('flow.message');
  if(kLabel)kLabel.textContent=t('flow.key');
  const scard=document.getElementById('scard');
  if(scard&&(!steps.length||!scard.classList.contains('active')))scard.innerHTML=`<div style="text-align:center;padding:38px;color:var(--muted);font-family:'Fraunces',serif;font-size:1rem">${t('flow.empty.html')}</div>`;
  const outLbl=document.querySelector('#out-blk .out-lbl');if(outLbl)outLbl.textContent=t('flow.cipher');
  const dec=document.querySelector('#dec-box strong');if(dec)dec.textContent=t('flow.decrypted');
}
function applyDynamicTranslations(){
  COURSE_STAGES.forEach(stage=>{
    const keys=COURSE_STAGE_KEYS[stage.id];
    if(keys){stage.label=t(keys[0]);stage.note=t(keys[1]);}
  });
  document.querySelectorAll('[data-stage-btn]').forEach(btn=>{
    const stage=COURSE_STAGES.find(s=>s.id===btn.dataset.stageBtn);
    if(stage)btn.textContent=stage.label;
  });
  const active=COURSE_STAGES[activeCourseStage]||COURSE_STAGES[0];
  const toggle=document.getElementById('stage-menu-toggle');if(toggle)toggle.textContent=active.label;
  const prev=document.querySelector('.stagebar .stage-arrow:first-child');if(prev)prev.textContent=t('btn.prev');
  const next=document.querySelector('.stagebar .stage-arrow:last-child');if(next)next.textContent=t('btn.next');
  const map=document.querySelector('.stage-map-btn');if(map)map.textContent=t('btn.map');
  const settings=document.querySelector('.stage-settings-btn');if(settings)settings.textContent=t('btn.settings');
  const btnPrev=document.getElementById('btnprev');if(btnPrev)btnPrev.textContent=t('btn.prev');
  const btnReplay=document.getElementById('btnreplay');if(btnReplay)btnReplay.textContent=t('btn.replay');
  const speedLabel=document.getElementById('player-speed-label');if(speedLabel)speedLabel.textContent=t('settings.speed');
  const playerSpeed=document.getElementById('player-speed');
  if(playerSpeed){
    const keys=['settings.slow','settings.default','settings.fast'];
    [...playerSpeed.options].forEach((opt,i)=>opt.textContent=t(keys[i]||'settings.default'));
  }
  const aiBtn=document.querySelector('.ai-helper-btn span:last-child');if(aiBtn)aiBtn.textContent=t('ai.button');
  const aiName=document.querySelector('.ai-helper-head strong');if(aiName)aiName.textContent=t('ai.name');
  const aiSub=document.querySelector('.ai-helper-head small');if(aiSub)aiSub.textContent=t('ai.subtitle');
  const aiInput=document.getElementById('ai-question');if(aiInput)aiInput.placeholder=t('ai.placeholder');
  const aiSend=document.querySelector('.ai-chat-input button');if(aiSend)aiSend.textContent=t('btn.send');
  const quick=document.querySelectorAll('.ai-quick button');
  if(quick[0])quick[0].textContent=t('ai.quick.step');
  if(quick[1])quick[1].textContent=t('ai.quick.hint');
  if(quick[2])quick[2].textContent=t('ai.quick.key');
  const dynIds={
    'calc-title':'calc.title','calc-standard-label':'calc.standard','calc-history-label':'calc.history',
    'xor-tool-label':'calc.xor','xor-a-label':'calc.xorA','xor-b-label':'calc.xorB','xor-run-btn':'calc.xorRun'
  };
  Object.entries(dynIds).forEach(([id,key])=>{const el=document.getElementById(id);if(el)el.textContent=t(key);});
  const firstBot=document.querySelector('#ai-chat-log .ai-msg.bot:first-child');
  if(firstBot&&firstBot.dataset.seed!=='custom'){firstBot.textContent=t('ai.hello');firstBot.dataset.seed='custom';}
  updateSettingsLabels();
  updateSideInstruction(steps[curIdx]);
  updateScoreHud();
  updateCalcDisplay();
  renderCalcHistory();
  syncAesCalculator();
  syncResultPanel();
}
function applyTranslations(){
  document.documentElement.lang=siteSettings.lang==='kz'?'kk':siteSettings.lang==='ru'?'ru':'en';
  applyStaticTranslations();
  applyDynamicTranslations();
}
function saveSettings(){
  try{localStorage.setItem('aesLearnSettings',JSON.stringify(siteSettings));}catch(err){}
}
function loadSettings(){
  try{
    const saved=JSON.parse(localStorage.getItem('aesLearnSettings')||'{}');
    siteSettings=Object.assign(siteSettings,saved);
    siteSettings.speed=normalizeSpeed(siteSettings.speed);
  }catch(err){}
}
function normalizeSpeed(value){
  if(value==='slow'||value==='medium'||value==='fast')return value;
  const n=Number(value);
  if(!Number.isFinite(n))return 'medium';
  if(n<=.6)return 'slow';
  if(n<=1.4)return 'medium';
  return 'fast';
}
function speedDelay(){
  return {slow:5000,medium:3000,fast:1000}[normalizeSpeed(siteSettings.speed)]||3000;
}
function applySettings(){
  document.body.classList.toggle('theme-night',siteSettings.theme==='night');
  document.body.classList.toggle('high-contrast',!!siteSettings.contrast);
  siteSettings.speed=normalizeSpeed(siteSettings.speed);
  const delay=speedDelay();
  document.documentElement.style.setProperty('--font-scale',String((siteSettings.font||100)/100));
  document.documentElement.style.setProperty('--scheme-speed',`${delay/1000}s`);
  document.documentElement.style.setProperty('--flip-speed','.28s');
  updateSettingsControls();
  applyTranslations();
}
function setSiteSetting(key,value){
  if(key==='font')value=Number(value)||100;
  if(key==='speed')value=normalizeSpeed(value);
  if(key==='contrast')value=!!value;
  siteSettings[key]=value;
  saveSettings();
  applySettings();
  if(key==='lang'&&steps.length)rebuildLocalizedSteps();
}
function animDelay(ms){
  return speedDelay();
}
function rebuildLocalizedSteps(){
  const p=document.getElementById('pIn'),k=document.getElementById('kIn');
  if(!p||!k||!steps.length||k.value.length!==32)return;
  const oldIdx=curIdx;
  steps=buildSteps(p.value,getKey());
  curIdx=Math.min(oldIdx,steps.length-1);
  buildTrack();
  renderStep(curIdx);
}
function createSettingsPanel(){
  if(document.getElementById('settings-panel'))return;
  const panel=document.createElement('div');
  panel.className='settings-panel';
  panel.id='settings-panel';
  panel.innerHTML=`<div class="settings-card">
    <div class="settings-head"><strong id="settings-title"></strong><button onclick="toggleSettingsPanel(false)" aria-label="Close settings">x</button></div>
    <label><span id="settings-lang-label"></span><select id="setting-lang" onchange="setSiteSetting('lang',this.value)"><option value="us">US</option><option value="kz">KZ</option><option value="ru">RU</option></select></label>
    <label><span id="settings-theme-label"></span><select id="setting-theme" onchange="setSiteSetting('theme',this.value)"><option value="light" id="setting-theme-light"></option><option value="night" id="setting-theme-night"></option></select></label>
    <label><span id="settings-font-label"></span><input id="setting-font" type="range" min="85" max="125" step="5" oninput="setSiteSetting('font',this.value)"><output id="setting-font-value"></output></label>
    <label><span id="settings-contrast-label"></span><input id="setting-contrast" type="checkbox" onchange="setSiteSetting('contrast',this.checked)"></label>
    <label><span id="settings-speed-label"></span><select id="setting-speed" onchange="setSiteSetting('speed',this.value)"><option value="slow" id="speed-slow"></option><option value="medium" id="speed-default"></option><option value="fast" id="speed-fast"></option></select></label>
    <button class="btn-p settings-replay" onclick="replayCurrentAnimation()" id="settings-replay"></button>
  </div>`;
  document.body.appendChild(panel);
}
function updateSettingsLabels(){
  const ids={
    'settings-title':'settings.title','settings-lang-label':'settings.lang','settings-theme-label':'settings.theme','settings-font-label':'settings.font',
    'settings-contrast-label':'settings.contrast','settings-speed-label':'settings.speed','settings-replay':'settings.replay',
    'setting-theme-light':'settings.light','setting-theme-night':'settings.night','speed-slow':'settings.slow','speed-default':'settings.default',
    'speed-fast':'settings.fast'
  };
  Object.entries(ids).forEach(([id,key])=>{const el=document.getElementById(id);if(el)el.textContent=t(key);});
}
function updateSettingsControls(){
  const lang=document.getElementById('setting-lang'),theme=document.getElementById('setting-theme'),font=document.getElementById('setting-font'),contrast=document.getElementById('setting-contrast'),speed=document.getElementById('setting-speed'),playerSpeed=document.getElementById('player-speed'),fv=document.getElementById('setting-font-value');
  if(lang)lang.value=siteSettings.lang;
  if(theme)theme.value=siteSettings.theme;
  if(font)font.value=siteSettings.font;
  if(contrast)contrast.checked=!!siteSettings.contrast;
  if(speed)speed.value=String(siteSettings.speed);
  if(playerSpeed)playerSpeed.value=String(siteSettings.speed);
  if(fv)fv.textContent=`${siteSettings.font}%`;
}
function toggleSettingsPanel(force){
  const panel=document.getElementById('settings-panel');if(!panel)return;
  const open=typeof force==='boolean'?force:!panel.classList.contains('open');
  panel.classList.toggle('open',open);
}
function replayCurrentAnimation(){
  if(steps.length&&steps[curIdx])renderStep(curIdx);
  else animRounds();
}

function resetPracticeScore(){
  practiceScore=0;
  scoredChallenges.clear();
  challengeAttempts.clear();
  updateScoreHud();
}
function updateScoreHud(){
  const score=document.getElementById('practice-score-value');
  const attempts=document.getElementById('practice-attempts-value');
  const label=document.getElementById('practice-score-label');
  const attemptLabel=document.getElementById('practice-attempts-label');
  const wrong=challengeAttempts.get(curIdx)||0;
  const currentSolved=solvedChallenges.has(curIdx);
  const currentCorrect=scoredChallenges.has(curIdx);
  const currentAttempts=currentSolved?(wrong>=3&&!currentCorrect?3:wrong+1):wrong;
  if(score)score.textContent=String(practiceScore);
  if(attempts)attempts.textContent=steps[curIdx]&&steps[curIdx].challenge?`${currentAttempts}/3`:'-';
  if(label)label.textContent=t('score.points');
  if(attemptLabel)attemptLabel.textContent=t('score.attempts');
}
function challengeSkill(s){
  if(!s)return t('score.skill.general');
  if(s.skill)return s.skill;
  if(s.isINPUT)return t('score.skill.input');
  if(s.isKEY)return t('score.skill.key');
  if(s.isARK)return t('score.skill.xor');
  if(s.isSUB)return t('score.skill.sbox');
  if(s.isSH)return t('score.skill.shift');
  if(s.isMX)return t('score.skill.mix');
  if(s.schemeStep)return t('score.skill.rounds');
  return t('score.skill.general');
}
function scoreSummary(){
  const challengeSteps=steps.map((s,i)=>({s,i})).filter(x=>x.s.challenge);
  const maxScore=challengeSteps.length*30;
  const totalAttempts=challengeSteps.reduce((sum,x)=>{
    const mistakes=challengeAttempts.get(x.i)||0;
    const solved=solvedChallenges.has(x.i);
    const correct=scoredChallenges.has(x.i);
    return sum+(solved?(mistakes>=3&&!correct?3:mistakes+1):mistakes);
  },0);
  const mistakes=challengeSteps.reduce((sum,x)=>sum+(challengeAttempts.get(x.i)||0),0);
  const correct=challengeSteps.filter(x=>scoredChallenges.has(x.i)).length;
  const percent=maxScore?Math.max(0,Math.min(100,Math.round((practiceScore/maxScore)*100))):0;
  const weak=challengeSteps
    .map(x=>{
      const wrong=challengeAttempts.get(x.i)||0;
      const correctHere=scoredChallenges.has(x.i);
      const solved=solvedChallenges.has(x.i);
      const attempts=solved?(wrong>=3&&!correctHere?3:wrong+1):wrong;
      return {idx:x.i,skill:challengeSkill(x.s),attempts,mistakes:wrong};
    })
    .sort((a,b)=>b.mistakes-a.mistakes||b.attempts-a.attempts)[0];
  const weakText=weak&&weak.mistakes>0?t('score.weakDetail',{skill:weak.skill,attempts:weak.attempts}):t('score.weakNone');
  return {totalAttempts,mistakes,correct,maxScore,percent,weakText};
}
function renderPracticeSummary(){
  const sum=scoreSummary();
  const tone=sum.percent>=80?'good':sum.percent>=50?'mid':'low';
  return `<div class="practice-summary ${tone}">
    <div class="summary-gauge" style="--angle:${sum.percent*1.8}deg">
      <div class="gauge-center"><strong>${sum.percent}%</strong><span>${t('score.success')}</span></div>
    </div>
    <div class="summary-stats">
      <div><span>${t('score.final')}</span><strong>${practiceScore}</strong></div>
      <div><span>${t('score.max')}</span><strong>${sum.maxScore}</strong></div>
      <div><span>${t('score.correct')}</span><strong>${sum.correct}</strong></div>
      <div><span>${t('score.mistakes')}</span><strong>${sum.mistakes}</strong></div>
      <div><span>${t('score.totalAttempts')}</span><strong>${sum.totalAttempts}</strong></div>
      <p>${sum.weakText}</p>
    </div>
  </div>`;
}

function hexCompact(bytes){
  return bytes.map(H).join('').toLowerCase();
}
function bytesToBase64(bytes){
  return btoa(String.fromCharCode(...bytes));
}

function createResultSection(){
  if(document.getElementById('result-sec'))return;
  const sec=document.createElement('section');
  sec.className='result-sec';
  sec.id='result-sec';
  sec.innerHTML=`<div class="sec">
    <div class="stag fi">${t('result.stage')}</div>
    <h2 class="sh fi">${t('result.title')}</h2>
    <p class="sd fi">${t('result.desc')}</p>
    <div class="flow-inp fi">
      <div class="fi-title">${t('result.latest')}</div>
      <div class="fi-sub">${t('result.sub')}</div>
      <div class="result-meta">
        <div><span>${t('result.key')}</span><strong id="result-key">-</strong></div>
        <div><span>${t('result.mode')}</span><strong id="result-mode-label">ECB</strong></div>
        <div><span>${t('result.format')}</span><strong id="result-format-label">HEX</strong></div>
      </div>
      <div class="out-val" id="result-cipher">${t('result.none')}</div>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-p" id="result-back-btn" onclick="navigateToStage('encrypt')">${t('btn.backPractice')}</button>
        <button class="btn-o" id="result-decrypt-btn" onclick="runDec();syncResultPanel()">${t('btn.decrypt')}</button>
        <a class="btn-o" id="result-external-link" href="https://anycript.com/crypto" target="_blank" rel="noopener">${t('result.external')}</a>
        <button class="btn-o" id="result-map-btn" onclick="openAesMap()">${t('btn.map')}</button>
      </div>
      <div class="dec-box" id="result-dec-box" style="display:none"><strong>${t('flow.decrypted')}</strong> <span id="result-dec-txt">-</span></div>
    </div>
  </div>`;
  const team=document.getElementById('team');
  document.body.insertBefore(sec,team||document.querySelector('footer'));
}

function createStageControls(){
  if(document.getElementById('stagebar'))return;
  const bar=document.createElement('div');
  bar.className='stagebar';
  bar.id='stagebar';
  bar.innerHTML=`<button class="stage-arrow" onclick="prevStage()">${t('btn.prev')}</button>
    <div class="stage-menu-wrap">
      <button class="stage-menu-toggle" id="stage-menu-toggle" onclick="toggleStageMenu()">Stages</button>
      <div class="stage-menu" id="stage-menu">
        ${COURSE_STAGES.map(s=>`<button data-stage-btn="${s.id}" onclick="navigateToStage('${s.id}');closeStageMenu()">${s.label}</button>`).join('')}
      </div>
    </div>
    <button class="stage-map-btn" onclick="openAesMap()">${t('btn.map')}</button>
    <button class="stage-settings-btn" onclick="toggleSettingsPanel()">${t('btn.settings')}</button>
    <button class="stage-arrow" onclick="nextStage()">${t('btn.next')}</button>
    <div class="ai-helper-wrap" id="ai-helper-wrap">
      <button class="ai-helper-btn" onclick="toggleAiHelper()" aria-label="Open AI helper"><span class="octo"><i></i></span><span>${t('ai.button')}</span></button>
      <div class="ai-helper-panel" id="ai-helper-panel">
        <div class="ai-helper-head"><span class="octo big"><i></i></span><div><strong>${t('ai.name')}</strong><small>${t('ai.subtitle')}</small></div></div>
        <div class="ai-chat-log" id="ai-chat-log"><div class="ai-msg bot">${t('ai.hello')}</div></div>
        <div class="ai-chat-input"><input id="ai-question" placeholder="${t('ai.placeholder')}" onkeydown="if(event.key==='Enter')sendAiQuestion()"><button onclick="sendAiQuestion()">${t('btn.send')}</button></div>
        <div class="ai-quick"><button onclick="askAiHelper('step')">${t('ai.quick.step')}</button><button onclick="askAiHelper('hint')">${t('ai.quick.hint')}</button><button onclick="askAiHelper('key')">${t('ai.quick.key')}</button></div>
      </div>
    </div>`;
  document.body.appendChild(bar);
}

function toggleStageMenu(){const bar=document.getElementById('stagebar');if(bar)bar.classList.toggle('open');}
function closeStageMenu(){const bar=document.getElementById('stagebar');if(bar)bar.classList.remove('open');}
function toggleAiHelper(){const wrap=document.getElementById('ai-helper-wrap');if(wrap)wrap.classList.toggle('open');}
function closeAiHelper(){const wrap=document.getElementById('ai-helper-wrap');if(wrap)wrap.classList.remove('open');}
function parseHexByteToken(token){
  const clean=String(token||'').replace(/^0x/i,'').toUpperCase();
  return /^[0-9A-F]{2}$/.test(clean)?parseInt(clean,16):null;
}
const CLAUDE_AES_SYSTEM_PROMPT='You are Claude inside an AES-256 teaching tool for students. Teach step by step, be concise, use the current AES stage context, explain calculations with small examples, never give unrelated content, and encourage the student to inspect the matrices and solve Student Checks themselves.';
function askAiHelper(kind){
  const stage=COURSE_STAGES[activeCourseStage]||COURSE_STAGES[0];
  const current=steps[curIdx];
  if(kind==='step')appendAiMessage('bot',current?`${current.badge}: ${current.why}`:`You are in ${stage.label}. ${stage.note}`);
  if(kind==='hint')appendAiMessage('bot',current&&current.challenge?current.challenge.hint:'Follow the stage order, then use AES Map when you need to see where this step sits.');
  if(kind==='key')appendAiMessage('bot',t('ai.key.rule'));
}
function appendAiMessage(role,text){
  const log=document.getElementById('ai-chat-log');if(!log)return;
  const msg=document.createElement('div');
  msg.className=`ai-msg ${role}`;
  msg.textContent=text;
  log.appendChild(msg);
  log.scrollTop=log.scrollHeight;
  return msg;
}
function claudeProxyUrl(){
  return (window.CLAUDE_AES_PROXY_URL||localStorage.getItem('claudeAesProxyUrl')||'').trim();
}
function claudeLessonContext(){
  const stage=COURSE_STAGES[activeCourseStage]||COURSE_STAGES[0],current=steps[curIdx];
  return {
    stage:stage.label,
    step:current?current.badge:null,
    stepTitle:current?current.title:null,
    stepWhy:current?current.why:null,
    instruction:current?stepInstructionText(current):stage.note,
    challenge:current&&current.challenge?current.challenge.prompt:null
  };
}
async function askClaudeTutor(question){
  const url=claudeProxyUrl();
  if(!url)return null;
  const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
    system:t('ai.system')||CLAUDE_AES_SYSTEM_PROMPT,
    message:question,
    context:claudeLessonContext()
  })});
  if(!res.ok)throw new Error(`Claude proxy returned ${res.status}`);
  const data=await res.json();
  return data.answer||data.text||(data.content&&data.content[0]&&data.content[0].text)||null;
}
async function sendAiQuestion(){
  const input=document.getElementById('ai-question');if(!input)return;
  const q=input.value.trim();if(!q)return;
  appendAiMessage('user',q);
  input.value='';
  const pending=appendAiMessage('bot',t('ai.thinking'));
  try{
    const claudeAnswer=await askClaudeTutor(q);
    pending.textContent=claudeAnswer||answerAiQuestion(q);
  }catch(err){
    pending.textContent=`${t('ai.fallback')}\n\n${answerAiQuestion(q)}`;
  }
}
function answerAiQuestion(q){
  const low=q.toLowerCase(),current=steps[curIdx];
  const xor=q.match(/(?:0x)?([0-9a-fA-F]{2})\s*(?:xor|\^)\s*(?:0x)?([0-9a-fA-F]{2})/);
  if(xor){const a=parseInt(xor[1],16),b=parseInt(xor[2],16);return t('ai.xor',{a:H(a),b:H(b),r:H(a^b),ab:B8(a),bb:B8(b),rb:B8(a^b)});}
  const ascii=q.match(/ascii\s+(0x[0-9a-fA-F]{2}|.)/i);
  if(ascii){const raw=ascii[1],n=raw.toLowerCase().startsWith('0x')?parseInt(raw,16):raw.charCodeAt(0);return t('ai.ascii',{raw,n,hex:H(n),bits:B8(n)});}
  const sbox=q.match(/s-?box\s*(?:of)?\s*(?:0x)?([0-9a-fA-F]{2})/i);
  if(sbox){const n=parseInt(sbox[1],16);return t('ai.sbox',{byte:H(n),row:H(n)[0],col:H(n)[1],out:H(SB[n])});}
  if(low.includes('key')||low.includes('256'))return t('ai.key');
  if(low.includes('history')||low.includes('who made')||low.includes('when'))return t('ai.history');
  if(low.includes('ascii')||low.includes('character')||low.includes('text'))return t('ai.text');
  if(low.includes('byte')||low.includes('bit'))return t('ai.byte');
  if(low.includes('sbox')||low.includes('s-box')||low.includes('subbyte'))return t('ai.sbox.basic');
  if(low.includes('xor')||low.includes('addround'))return t('ai.xor.basic');
  if(low.includes('ecb')||low.includes('mode'))return t('ai.ecb');
  if(low.includes('gf')||low.includes('field'))return t('ai.gf');
  if(low.includes('shift'))return t('ai.shift');
  if(low.includes('mix'))return t('ai.mix');
  if(low.includes('padding')||low.includes('pkcs'))return t('ai.padding');
  if(low.includes('round'))return t('ai.round');
  if(low.includes('result')||low.includes('cipher'))return t('ai.result');
  if(low.includes('current')||low.includes('step'))return current?`${current.badge}: ${current.why}`:'Open Practice and I can explain the active AES step.';
  return t('ai.default');
}

function createSideTools(){
  if(document.getElementById('tool-left'))return;
  const left=document.createElement('aside');
  left.className='stage-tools left';
  left.id='tool-left';
  left.innerHTML=`<button class="tool-pin" onclick="toggleToolPin('tool-left')" aria-label="Pin AES calculator"><span class="pin-icon"></span></button><div class="tool-title" id="calc-title">${t('calc.title')}</div>
    <div class="aes-calc">
      <div class="calc-top"><span id="calc-standard-label">${t('calc.standard')}</span><button type="button" onclick="syncAesCalculator()">AES</button></div>
      <div class="calc-sub" id="calc-mini">${t('calc.ready')}</div>
      <div class="calc-screen" id="calc-result">0</div>
      <div class="calc-memory"><span>MC</span><span>MR</span><span>M+</span><span>M-</span><span>MS</span></div>
      <div class="calc-pad">
        <button onclick="calcPercent()">%</button><button onclick="calcClear()">CE</button><button onclick="calcClear()">C</button><button onclick="calcBackspace()">Back</button>
        <button onclick="calcUnary('recip')">1/x</button><button onclick="calcUnary('square')">x^2</button><button onclick="calcUnary('sqrt')">sqrt</button><button onclick="calcChooseOp('/')">/</button>
        <button onclick="calcPress('7')">7</button><button onclick="calcPress('8')">8</button><button onclick="calcPress('9')">9</button><button onclick="calcChooseOp('*')">*</button>
        <button onclick="calcPress('4')">4</button><button onclick="calcPress('5')">5</button><button onclick="calcPress('6')">6</button><button onclick="calcChooseOp('-')">-</button>
        <button onclick="calcPress('1')">1</button><button onclick="calcPress('2')">2</button><button onclick="calcPress('3')">3</button><button onclick="calcChooseOp('+')">+</button>
        <button onclick="calcToggleSign()">+/-</button><button onclick="calcPress('0')">0</button><button onclick="calcPress('.')">.</button><button class="equals" onclick="runCalculator()">=</button>
      </div>
    </div>
    <div class="tool-note" id="aes-calc-info"></div>
    <div class="tool-card xor-tool"><label id="xor-tool-label">${t('calc.xor')}</label>
      <label id="xor-a-label" class="sub-label">${t('calc.xorA')}</label><input id="xor-a" placeholder="5C 16 A3" oninput="runXorCalc(false)">
      <label id="xor-b-label" class="sub-label">${t('calc.xorB')}</label><input id="xor-b" placeholder="A0 FF 01" oninput="runXorCalc(false)">
      <button class="btn-p calc-run" id="xor-run-btn" onclick="runXorCalc(true)">${t('calc.xorRun')}</button>
      <div class="tool-result" id="xor-result">${t('calc.xorEmpty')}</div>
    </div>
    <div class="tool-card"><label id="calc-history-label">${t('calc.history')}</label><div class="calc-history" id="calc-history"></div></div>`;
  const right=document.createElement('aside');
  right.className='stage-tools right';
  right.id='tool-right';
  right.innerHTML=`<button class="tool-pin" onclick="toggleToolPin('tool-right')" aria-label="Pin current step"><span class="pin-icon"></span></button><div class="tool-title">Current AES Step</div>
    <p class="tool-note" id="stage-note">Use Next to move through the AES course.</p>
    <div class="tool-card aes-remind-card" onclick="showRandomAesCard()" title="Click for another card"><label id="aes-side-title">Interesting card</label><p class="tool-note" id="aes-side-body">AES is not hiding letters one by one. One changed bit spreads through the state until the ciphertext looks unrelated to the message.</p></div>
    <div class="tool-card instruction-card"><label id="aes-instruction-title">Instruction</label><p class="tool-note" id="aes-instruction-body">The current calculation instruction will appear here during Theory Tasks and Practice.</p></div>`;
  const asciiBar=document.createElement('aside');
  asciiBar.className='bottom-ref-tools left';
  asciiBar.id='ref-ascii';
  asciiBar.innerHTML=`<button class="tool-pin" onclick="toggleToolPin('ref-ascii')" aria-label="Pin ASCII reference"><span class="pin-icon"></span></button><div class="bottom-ref-title">ASCII</div><div class="mini-ref" id="tool-ascii-table"></div>`;
  const sboxBar=document.createElement('aside');
  sboxBar.className='bottom-ref-tools right';
  sboxBar.id='ref-sbox';
  sboxBar.innerHTML=`<button class="tool-pin" onclick="toggleToolPin('ref-sbox')" aria-label="Pin S-Box reference"><span class="pin-icon"></span></button><div class="bottom-ref-title">S-Box</div><div class="mini-ref sbox-ref" id="tool-sbox-table"></div>`;
  document.body.append(left,right,asciiBar,sboxBar);
  ['pIn','kIn'].forEach(id=>{const el=document.getElementById(id);if(el)el.addEventListener('input',syncAesCalculator);});
  syncAesCalculator();
  updateCalcDisplay();
  showRandomAesCard();
  renderCalcHistory();
  buildToolReferenceTables();
  updateSideInstruction(steps[curIdx]);
}

function toggleToolPin(id){
  const panel=document.getElementById(id);if(!panel)return;
  panel.classList.toggle('pinned');
}

function showRandomAesCard(){
  const types=Object.keys(AES_SIDE_CARDS);
  const type=types[Math.floor(Math.random()*types.length)];
  const list=AES_SIDE_CARDS[type];
  const bodyText=list[Math.floor(Math.random()*list.length)];
  const title=document.getElementById('aes-side-title'),body=document.getElementById('aes-side-body');
  if(title)title.textContent=`${type.charAt(0).toUpperCase()+type.slice(1)} card`;
  if(body)body.textContent=bodyText;
}

function createFinishCelebration(){
  if(document.getElementById('finish-celebration'))return;
  const box=document.createElement('div');
  box.className='finish-celebration';
  box.id='finish-celebration';
  box.innerHTML='<div class="finish-card"><h3>Congratulations!</h3><p>AES encryption walkthrough complete.</p></div>';
  document.body.appendChild(box);
}
function playApplause(){
  try{
    const AudioCtx=window.AudioContext||window.webkitAudioContext;
    if(!AudioCtx)return;
    const ctx=new AudioCtx();
    const master=ctx.createGain();
    master.gain.value=.12;
    master.connect(ctx.destination);
    for(let i=0;i<18;i++){
      const t=ctx.currentTime+i*.055;
      const src=ctx.createBufferSource();
      const buffer=ctx.createBuffer(1,ctx.sampleRate*.08,ctx.sampleRate);
      const data=buffer.getChannelData(0);
      for(let j=0;j<data.length;j++)data[j]=(Math.random()*2-1)*(1-j/data.length);
      src.buffer=buffer;
      const gain=ctx.createGain();
      gain.gain.setValueAtTime(0,t);
      gain.gain.linearRampToValueAtTime(.8,t+.008);
      gain.gain.exponentialRampToValueAtTime(.01,t+.08);
      src.connect(gain).connect(master);
      src.start(t);
    }
    setTimeout(()=>ctx.close(),1600);
  }catch(err){}
}
function launchFinishCelebration(){
  createFinishCelebration();
  const box=document.getElementById('finish-celebration');if(!box)return;
  box.querySelectorAll('.confetti-piece').forEach(el=>el.remove());
  const colors=['#0b6e62','#9a6c08','#c04818','#523092','#186038','#a01818'];
  for(let i=0;i<72;i++){
    const c=document.createElement('i');
    c.className='confetti-piece';
    c.style.left=Math.random()*100+'vw';
    c.style.background=colors[i%colors.length];
    c.style.animationDelay=(Math.random()*.55)+'s';
    c.style.animationDuration=(2.1+Math.random()*1.2)+'s';
    box.appendChild(c);
  }
  box.classList.remove('show');void box.offsetWidth;box.classList.add('show');
  playApplause();
  setTimeout(()=>box.classList.remove('show'),3400);
}

function formatCalc(n){
  if(!isFinite(n))return 'Error';
  const fixed=Number(n.toFixed(10));
  return String(fixed);
}
function updateCalcDisplay(){
  const out=document.getElementById('calc-result');if(out)out.textContent=calcValue;
  const mini=document.getElementById('calc-mini');if(mini)mini.textContent=calcStored!==null&&calcOp?`${formatCalc(calcStored)} ${calcOp}`:t('calc.ready');
}
function calcPress(ch){
  if(calcReset){calcValue='0';calcReset=false;}
  if(ch==='.'&&calcValue.includes('.'))return;
  calcValue=calcValue==='0'&&ch!=='.'?ch:calcValue+ch;
  updateCalcDisplay();
}
function calcClear(){calcValue='0';calcStored=null;calcOp=null;calcReset=false;updateCalcDisplay();}
function calcBackspace(){calcValue=calcValue.length>1?calcValue.slice(0,-1):'0';updateCalcDisplay();}
function calcToggleSign(){if(calcValue!=='0')calcValue=calcValue.startsWith('-')?calcValue.slice(1):'-'+calcValue;updateCalcDisplay();}
function calcPercent(){calcValue=formatCalc(Number(calcValue)/100);updateCalcDisplay();}
function calcUnary(kind){
  const n=Number(calcValue);let result=n,label='';
  if(kind==='recip'){result=n===0?NaN:1/n;label=`1 / ${n}`;}
  if(kind==='square'){result=n*n;label=`${n} * ${n}`;}
  if(kind==='sqrt'){result=n<0?NaN:Math.sqrt(n);label=`sqrt(${n})`;}
  calcValue=formatCalc(result);
  calcHistory.unshift(`${label} = ${calcValue}`);
  calcHistory.splice(8);
  renderCalcHistory();
  updateCalcDisplay();
}
function calcChooseOp(op){
  if(calcStored!==null&&!calcReset)runCalculator(false);
  calcStored=Number(calcValue);calcOp=op;calcReset=true;updateCalcDisplay();
}
function runCalculator(save=true){
  if(calcStored===null||!calcOp){updateCalcDisplay();return;}
  const a=calcStored,b=Number(calcValue);
  let result=0;
  if(calcOp==='+')result=a+b;
  if(calcOp==='-')result=a-b;
  if(calcOp==='*')result=a*b;
  if(calcOp==='/')result=b===0?NaN:a/b;
  const label=`${formatCalc(a)} ${calcOp} ${formatCalc(b)}`;
  calcValue=formatCalc(result);
  if(save){
    calcHistory.unshift(`${label} = ${calcValue}`);
    calcHistory.splice(8);
    renderCalcHistory();
  }
  calcStored=null;calcOp=null;calcReset=true;updateCalcDisplay();
}
function syncAesCalculator(){
  const p=document.getElementById('pIn'),k=document.getElementById('kIn'),box=document.getElementById('aes-calc-info');
  if(!box)return;
  const plainLen=p?p.value.length:0,keyLen=k?k.value.length:0;
  box.textContent=t('calc.info',{plain:plainLen,key:keyLen,bits:keyLen*8});
}

function renderCalcHistory(){
  const box=document.getElementById('calc-history');if(!box)return;
  box.innerHTML=calcHistory.map(x=>`<div class="history-item">${escHtml(x)}</div>`).join('')||`<div class="history-item">${t('calc.noHistory')}</div>`;
}

function parseHexByteList(raw){
  const text=String(raw||'').trim();
  if(!text)return [];
  const clean=text.replace(/0x/gi,' ').replace(/[^0-9a-fA-F]+/g,' ').trim();
  if(!clean)return null;
  let parts=clean.split(/\s+/).filter(Boolean);
  if(parts.length===1&&parts[0].length>2)parts=parts[0].match(/.{1,2}/g)||[];
  const bytes=[];
  for(const part of parts){
    if(part.length>2||!/^[0-9a-fA-F]{1,2}$/.test(part))return null;
    bytes.push(parseInt(part,16)&255);
  }
  return bytes;
}
function runXorCalc(save=false){
  const aInput=document.getElementById('xor-a'),bInput=document.getElementById('xor-b'),box=document.getElementById('xor-result');
  if(!box)return;
  const a=parseHexByteList(aInput&&aInput.value),b=parseHexByteList(bInput&&bInput.value);
  if(a===null||b===null){box.textContent=t('calc.xorError');return;}
  if(!a.length||!b.length){box.textContent=t('calc.xorEmpty');return;}
  const len=Math.max(a.length,b.length);
  const out=Array.from({length:len},(_,i)=>a[i%a.length]^b[i%b.length]);
  const fmt=list=>list.map(x=>H(x)).join(' ');
  const line=`${fmt(a)} XOR ${fmt(b)} = ${fmt(out)}`;
  box.innerHTML=`<strong>${fmt(out)}</strong><span>${escHtml(line)}</span>`;
  if(save){
    calcHistory.unshift(line);
    calcHistory.splice(8);
    renderCalcHistory();
  }
}

function buildToolReferenceTables(){
  const ascii=document.getElementById('tool-ascii-table');
  if(ascii){
    ascii.classList.add('ascii-ref');
    ascii.innerHTML='<table><thead><tr><th>Char</th><th>Dec</th><th>Hex</th></tr></thead><tbody></tbody></table>';
    const body=ascii.querySelector('tbody');
    for(let i=32;i<=126;i++){
      const tr=document.createElement('tr');
      tr.innerHTML=`<td>${escHtml(String.fromCharCode(i))}</td><td>${i}</td><td>${H(i)}</td>`;
      body.appendChild(tr);
    }
  }
  const sbox=document.getElementById('tool-sbox-table');
  if(sbox){
    sbox.innerHTML='<table><thead></thead><tbody></tbody></table>';
    const head=sbox.querySelector('thead'),body=sbox.querySelector('tbody');
    head.innerHTML='<tr><th></th>'+Array.from({length:16},(_,i)=>`<th>${i.toString(16).toUpperCase()}</th>`).join('')+'</tr>';
    for(let r=0;r<16;r++){
      const tr=document.createElement('tr');
      tr.innerHTML=`<th>${r.toString(16).toUpperCase()}</th>`+Array.from({length:16},(_,c)=>`<td title="${H(r*16+c)} -> ${H(SB[r*16+c])}">${H(SB[r*16+c])}</td>`).join('');
      body.appendChild(tr);
    }
  }
}

function createAesMapModal(){
  if(document.getElementById('aes-map-modal'))return;
  const modal=document.createElement('div');
  modal.className='aes-map-modal';
  modal.id='aes-map-modal';
  modal.innerHTML=`<div class="aes-map-card">
    <div class="aes-map-head"><h3>Block Scheme of AES Encryption</h3><button onclick="closeAesMap()">Close</button></div>
    <div class="aes-block-map aes-encryption-map">
      <svg class="aes-map-lines" viewBox="0 0 900 780" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <marker id="aes-map-arrow" markerWidth="14" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="userSpaceOnUse">
            <path d="M2 2 L10 6 L2 10"></path>
          </marker>
          <marker id="aes-map-key-arrow" markerWidth="14" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="userSpaceOnUse">
            <path d="M2 2 L10 6 L2 10"></path>
          </marker>
          <filter id="aes-map-soft-shadow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="7" stdDeviation="5" flood-color="#18120a" flood-opacity=".14"/>
          </filter>
        </defs>
        <path class="map-line" data-flow-pos="0" d="M450 86 L450 124"></path>
        <path class="map-line key-line" data-flow-pos="1" d="M108 156 H315"></path>
        <path class="map-line" data-flow-pos="1" d="M450 190 L450 232"></path>
        <path class="map-line key-line" data-flow-pos="5" d="M108 442 H315"></path>
        <path class="map-line" data-flow-pos="5" d="M450 482 L450 526"></path>
        <path class="map-line key-line" data-flow-pos="6" d="M108 660 H315"></path>
        <path class="map-line" data-flow-pos="6" d="M450 704 L450 738"></path>
        <path class="map-brace-line" d="M610 126 C632 126 626 136 626 158 C626 180 632 190 610 190"></path>
        <path class="map-brace-line" d="M610 236 C632 236 626 260 626 286 V424 C626 450 632 476 610 476"></path>
        <path class="map-brace-line" d="M610 530 C632 530 626 548 626 576 V652 C626 680 632 704 610 704"></path>
      </svg>
      <div class="map-title">Encryption</div>
      <div class="map-key-label key-initial">RoundKey</div>
      <div class="map-key-label key-repeat">RoundKey</div>
      <div class="map-key-label key-final">RoundKey</div>
      <div class="aes-node scheme-plain" data-map-pos="0">PlainText<small>16-byte block</small></div>
      <div class="aes-node scheme-ark" data-map-pos="1">AddRoundKey<small>1st round key XOR</small></div>
      <div class="map-round-label first-round">1st Round</div>
      <div class="aes-round-box repeat-round aes-map-group" data-map-pos="6">
        <div class="aes-round-step scheme-sub" data-map-pos="2">SubBytes</div>
        <div class="aes-round-step scheme-shift" data-map-pos="3">ShiftRows</div>
        <div class="aes-round-step scheme-mix" data-map-pos="4">MixColumns</div>
        <div class="aes-round-step scheme-ark2" data-map-pos="5">AddRoundKey</div>
      </div>
      <div class="map-round-label repeat-label">Repeat<br>N<sub>r</sub> - 1<br>Rounds</div>
      <div class="aes-round-box final-round aes-map-group" data-map-pos="6">
        <div class="aes-round-step scheme-sub">SubBytes</div>
        <div class="aes-round-step scheme-shift">ShiftRows</div>
        <div class="aes-round-step scheme-ark2">AddRoundKey</div>
      </div>
      <div class="map-round-label final-label">Last<br>Round</div>
      <div class="aes-node scheme-cipher" data-map-pos="7">CipherText<small>encrypted block</small></div>
      <div class="scheme-note-card">Green highlight shows the current place in the AES encryption scheme.</div>
    </div>
  </div>`;
  modal.addEventListener('click',e=>{if(e.target===modal)closeAesMap();});
  document.body.appendChild(modal);
}

function openAesMap(){const modal=document.getElementById('aes-map-modal');if(modal)modal.classList.add('open');updateAesMap();}
function closeAesMap(){const modal=document.getElementById('aes-map-modal');if(modal)modal.classList.remove('open');}

function updateAesMap(pos){
  const step=steps[curIdx];
  const fallback=activeCourseStage===0?0:activeCourseStage===1?2:activeCourseStage===2?3:activeCourseStage===3?Math.min(7,step&&Number.isInteger(step.mapPos)?step.mapPos:1):7;
  const active=Number.isInteger(pos)?pos:fallback;
  document.querySelectorAll('.aes-node,.aes-round-step,.aes-map-group').forEach(node=>{
    const nodePos=Number(node.dataset.mapPos);
    const hasPos=Number.isFinite(nodePos);
    node.classList.toggle('done',hasPos&&nodePos<active);
    node.classList.toggle('active',hasPos&&nodePos===active);
  });
  document.querySelectorAll('[data-flow-pos]').forEach(line=>{
    const flowPos=Number(line.dataset.flowPos);
    line.classList.toggle('active',flowPos===active||active===6&&flowPos===6);
  });
}

function navigateToStage(stageId){
  const idx=typeof stageId==='number'?stageId:COURSE_STAGES.findIndex(s=>s.id===stageId);
  if(idx<0)return;
  if(COURSE_STAGES[idx].id==='result'&&!encryptionComplete){
    alert(t('alert.result.locked'));
    closeStageMenu();
    return;
  }
  activeCourseStage=idx;
  const active=COURSE_STAGES[idx];
  const visible=new Set(active.sections);
  document.querySelectorAll('body > section').forEach(sec=>sec.classList.toggle('stage-hidden',!visible.has(sec.id)));
  const footer=document.querySelector('footer');if(footer)footer.style.display=active.id==='result'?'block':'none';
  const showTools=active.id==='tasks'||active.id==='encrypt';
  document.querySelectorAll('.stage-tools').forEach(panel=>{panel.style.display=showTools?'':'none';});
  document.querySelectorAll('.bottom-ref-tools').forEach(panel=>{panel.style.display=showTools?'':'none';});
  document.querySelectorAll('[data-stage-btn]').forEach(btn=>btn.classList.toggle('active',btn.dataset.stageBtn===active.id));
  const toggle=document.getElementById('stage-menu-toggle');if(toggle)toggle.textContent=active.label;
  const note=document.getElementById('stage-note');if(note)note.textContent=active.id==='encrypt'&&steps[curIdx]?stepInstructionText(steps[curIdx]):active.note;
  document.body.classList.add('stage-app');
  window.scrollTo({top:0,left:0,behavior:'auto'});
  document.querySelectorAll('.fi').forEach(el=>el.classList.add('on'));
  syncResultPanel();
  updateAesMap();
}
function nextStage(){navigateToStage(Math.min(activeCourseStage+1,COURSE_STAGES.length-1));}
function prevStage(){navigateToStage(Math.max(activeCourseStage-1,0));}

document.addEventListener('click',e=>{
  if(!e.target.closest('.stagebar')){closeStageMenu();closeAiHelper();}
  const a=e.target.closest('a[href^="#"]');if(!a)return;
  const id=a.getAttribute('href').slice(1);
  const stage=COURSE_STAGES.find(s=>s.sections.includes(id));
  if(!stage)return;
  e.preventDefault();
  navigateToStage(stage.id);
  setTimeout(()=>{const target=document.getElementById(id);if(target)target.scrollIntoView({behavior:'smooth',block:'start'});},50);
});

function syncResultPanel(){
  const out=document.getElementById('result-cipher');
  const keyInput=document.getElementById('kIn');
  const fmt='HEX';
  const mode='ECB';
  const key=keyInput?keyInput.value:'-';
  if(out)out.textContent=lastCipher?(fmt==='BASE64'?bytesToBase64(lastCipher):hexCompact(lastCipher)):t('result.none');
  const keyEl=document.getElementById('result-key'),modeEl=document.getElementById('result-mode-label'),fmtEl=document.getElementById('result-format-label');
  if(keyEl)keyEl.textContent=key||'-';
  if(modeEl)modeEl.textContent=mode==='CBC'?'CBC needs IV; walkthrough output is ECB':'ECB';
  if(fmtEl)fmtEl.textContent=fmt;
  const summary=document.getElementById('result-practice-summary');
  if(summary)summary.innerHTML='';
  const src=document.getElementById('dec-txt'),dst=document.getElementById('result-dec-txt'),box=document.getElementById('result-dec-box');
  if(src&&dst&&box&&src.textContent&&src.textContent!=='-'&&src.textContent!=='-'){dst.textContent=src.textContent;box.style.display='block';}
}

// Exact AES-256 key: students must see and use the real 32-byte requirement.
function getKey(raw){
  if(raw)return raw;
  const input=document.getElementById('kIn');
  const k=input?input.value:'';
  return k.split('').map(c=>c.charCodeAt(0));
}

function startEnc(){
  const plain=document.getElementById('pIn').value;
  const key=document.getElementById('kIn').value;
  if(!plain){alert(t('alert.enter'));return;}
  if(plain.length>15){alert(t('alert.short'));return;}
  if(key.length!==32){alert(t('alert.key',{n:key.length}));return;}
  const kb=getKey();
  solvedChallenges.clear();
  resetPracticeScore();
  encryptionComplete=false;
  celebrationShown=false;
  steps=buildSteps(plain,kb);
  lastCipher=encFull(plain,kb);
  curIdx=0;isPlaying=false;clearTimeout(playTimer);clearTimeout(animT);
  buildTrack();document.getElementById('player').style.display='block';
  document.getElementById('out-blk').classList.remove('show');document.getElementById('dec-box').style.display='none';
  renderStep(0);
  navigateToStage('encrypt');
}

function buildTrack(){
  const t=document.getElementById('ftrack');if(!t)return;t.innerHTML='';
  steps.forEach((s,i)=>{if(i>0){const l=document.createElement('div');l.className='ftline';l.id=`ftl${i-1}`;t.appendChild(l);}
    const d=document.createElement('div');d.className='ftd';d.id=`ftd${i}`;d.onclick=()=>goTo(i);
    d.innerHTML=`<div class="ftc">${i+1}</div><div class="ftlbl">${s.badge||('Step '+(i+1))}</div>`;t.appendChild(d);});
}

function goTo(i){
  stopPlay();
  if(i<=curIdx){curIdx=i;renderStep(i);return;}
  if(i===curIdx+1&&canLeaveCurrentStep()){curIdx=i;renderStep(i);return;}
  alert(t('alert.checks'));
}

function renderMatrixCompare(s,showByteDetail){
  if(s.isARK){
    return `<div class="sbody matrix-only">
      <div class="xor-stack">
        <div class="xor-top">
          <div class="matrix-panel">
            <div class="sg-lbl">${s.leftLabel||t('matrix.before')}</div>
            <div class="sgrid sgrid-before" id="sc-grid-before"></div>
          </div>
          <div class="matrix-symbol">${t('matrix.xor')}</div>
          <div class="matrix-panel">
            <div class="sg-lbl">${t('matrix.key')}</div>
            <div class="sgrid sgrid-key" id="sc-grid-key"></div>
          </div>
        </div>
        <div class="matrix-symbol equals xor-equals">${t('matrix.equals')}</div>
        <div class="xor-answer">
          <div class="matrix-panel">
            <div class="sg-lbl" id="sc-lbl">${s.glbl||t('matrix.result')}</div>
            <div class="sgrid sgrid-after" id="sc-grid-after"></div>
          </div>
        </div>
       </div>
      <div class="matrix-note wide" id="matrix-change-note">${t('matrix.hover')}</div>
    </div>
    ${showByteDetail?`<div class="sexpl byte-detail"><div class="se-lbl" id="sc-et">${s.et}</div><div class="se-fm" id="sc-fm">${s.fm||''}</div></div>`:''}`;
  }
  return `<div class="sbody matrix-only">
    <div class="matrix-compare">
      <div class="matrix-panel">
        <div class="sg-lbl">${s.leftLabel||t('matrix.before')}</div>
        <div class="sgrid sgrid-before" id="sc-grid-before"></div>
      </div>
      <div class="matrix-flow">
        <div class="matrix-op-chip">${operationShortLabel(s)}</div>
        <div class="matrix-arrow-line"><span></span></div>
        <div class="matrix-note" id="matrix-change-note">${t('matrix.hover')}</div>
      </div>
      <div class="matrix-panel">
        <div class="sg-lbl" id="sc-lbl">${s.glbl}</div>
        <div class="sgrid sgrid-after" id="sc-grid-after"></div>
      </div>
    </div>
  </div>
  ${showByteDetail?`<div class="sexpl byte-detail"><div class="se-lbl" id="sc-et">${s.et}</div><div class="se-fm" id="sc-fm">${s.fm||''}</div></div>`:''}`;
}

function renderSchemeStep(s){
  const rounds=['SubBytes','ShiftRows','MixColumns','AddRoundKey'];
  return `<div class="scheme-board">
    <div class="scheme-line"></div>
    <div class="scheme-dot"></div>
    <div class="scheme-start">After Round 1</div>
    <div class="scheme-repeat">
      <div class="scheme-round-label">Rounds 2-13 repeat 12 times</div>
      <div class="scheme-stack">${rounds.map((name,i)=>`<div class="scheme-node n${i}">${i+1}. ${name}</div>`).join('')}</div>
    </div>
    <div class="scheme-final-label">Round 14 final round</div>
    <div class="scheme-stack final">
      <div class="scheme-node n0">SubBytes</div>
      <div class="scheme-node n1">ShiftRows</div>
      <div class="scheme-node n3">AddRoundKey</div>
    </div>
    <div class="scheme-note">The green marker follows the AES block scheme: full rounds repeat, then the final round skips MixColumns.</div>
  </div>`;
}

function renderFinalCipherStep(s){
  const order=orderedStepIndices(s);
  const cells=order.map(i=>`<div class="scell matrix-cell revealed dnt"><span>${H(s.after[i])}</span><small>[${i}]</small></div>`).join('');
  return `<div class="cipher-final">
    <div class="sg-lbl">Ciphertext matrix</div>
    <div class="sgrid cipher-grid">${cells}</div>
    <div class="cipher-down"></div>
    <div class="cipher-line">${hexCompact(s.after)}</div>
    ${renderPracticeSummary()}
  </div>`;
}

function stepInstructionText(s,rel){
  if(!s)return t('instruction.default');
  if(s.schemeStep)return t('instruction.scheme');
  if(s.outputStep)return t('instruction.output');
  const idx=rel?rel.targetIdx:0,bv=s.before&&s.before[idx],av=s.after&&s.after[idx];
  if(s.isINPUT)return t('instruction.input',{ch:s.beforeChars&&s.beforeChars[0]||'s',dec:s.after[0],hex:H(s.after[0])});
  if(s.isKEY)return t('instruction.key',{hex:H(s.after[0])});
  if(s.isARK){
    const kv=keyByteFor(s,idx),result=av;
    return t('instruction.ark',{idx,before:H(bv),key:H(kv),after:H(result)});
  }
  if(s.isSUB){
    const hx=H(bv);
    return t('instruction.sub',{idx,byte:hx,row:hx[0],col:hx[1],after:H(av)});
  }
  if(s.isSH){
    const p=rel||relatedCells(s,idx,'after');
    return t('instruction.shift',{row:p.row,src:p.sourceIdx,dst:p.targetIdx});
  }
  if(s.isMX){
    const p=rel||relatedCells(s,idx,'after');
    return t('instruction.mix',{col:p.col,bytes:p.source.map(i=>H(s.before[i])).join(', '),idx:p.targetIdx,after:H(s.after[p.targetIdx])});
  }
  return s.challenge?s.challenge.hint:s.why;
}
function updateSideInstruction(s,rel){
  const text=stepInstructionText(s,rel);
  const note=document.getElementById('stage-note');
  if(note)note.textContent=text;
  const title=document.getElementById('aes-instruction-title'),body=document.getElementById('aes-instruction-body');
  if(title&&body){
    title.textContent=t('instruction.title');
    body.textContent=text;
  }
}

function renderStep(idx){
  clearTimeout(animT);renderGen++;
  const s=steps[idx];if(!s)return;
  steps.forEach((_,i)=>{const d=document.getElementById(`ftd${i}`);if(!d)return;d.className='ftd'+(i<idx?' done':i===idx?' active':'');if(i>0){const l=document.getElementById(`ftl${i-1}`);if(l)l.className='ftline'+(i<=idx?' done':'');}});
  const card=document.getElementById('scard');if(!card)return;
  card.className='scard active flip';void card.offsetWidth;
  const sbs=document.getElementById('sbox-sec');if(sbs){sbs.style.outline=s.showSboxHint?'3px solid var(--gold)':'';sbs.style.borderRadius=s.showSboxHint?'4px':'';}
  let html=`<div class="sbadge ${s.bc}">${s.badge}</div><div class="stitle">${s.title}</div><div class="swhy">${s.why}</div>`;
  if(s.showSboxHint)html+=`<div class="sbox-inline-hint"><strong>${t('matrix.sboxHint')}</strong></div>`;
  const showByteDetail=s.isARK||s.isSUB||s.isSH||s.isMX;
  if(s.schemeStep)html+=renderSchemeStep(s);
  else if(s.outputStep)html+=renderFinalCipherStep(s);
  else html+=renderMatrixCompare(s,showByteDetail);
  if(s.challenge)html+=renderChallenge(s.challenge);
  card.innerHTML=html;
  if(!s.schemeStep&&!s.outputStep)buildGrid(s,renderGen);
  updateSideInstruction(s);
  document.getElementById('pctr').textContent=t('step.counter',{n:idx+1,total:steps.length});
  document.getElementById('btnprev').disabled=idx===0;
  document.getElementById('btnnxt').textContent=idx===steps.length-1?t('btn.finish'):t('btn.next');
  document.getElementById('btnnxt').disabled=false;
  document.getElementById('pbf').style.width=`${steps.length>1?(idx/(steps.length-1))*100:100}%`;
  if(idx===steps.length-1&&lastCipher){
    encryptionComplete=true;
    document.getElementById('out-blk').classList.add('show');
    document.getElementById('out-val').textContent=hexCompact(lastCipher);
    syncResultPanel();
    if(!celebrationShown){
      celebrationShown=true;
      launchFinishCelebration();
    }
  }
  updateAesMap(s.mapPos);
}

function renderChallenge(ch){
  const maxLen=Math.max(ch.max||2,CHECK_OVERRIDE.length);
  let control=`<input id="step-answer" maxlength="${maxLen}" placeholder="${ch.placeholder||'??'}" oninput="this.value=this.value.toUpperCase()">`;
  if(ch.kind==='text')control=`<textarea id="step-answer" placeholder="${ch.placeholder||'Write your answer'}"></textarea>`;
  if(ch.kind==='choice')control=`<select id="step-answer" class="challenge-select"><option value="">Choose answer</option>${(ch.options||[]).map(o=>`<option value="${escHtml(o)}">${escHtml(o)}</option>`).join('')}</select>`;
  return `<div class="step-challenge"><h4>${t('student.check')}</h4><p>${ch.prompt}</p><div class="challenge-row">${control}<button class="chk-btn" onclick="checkStepAnswer()">${t('btn.check')}</button><button class="rvl-btn step-answer-btn" id="step-answer-btn" onclick="showStepAnswer()" style="display:none">${t('student.showAnswer')}</button></div><span class="challenge-feedback" id="challenge-feedback">${ch.hint}</span><div class="challenge-explain" id="challenge-explain"></div></div>`;
}

function challengeAnswerText(s){
  const ch=s&&s.challenge;
  if(!ch)return '';
  if(ch.answer!==undefined)return String(ch.answer).toUpperCase();
  return ch.sampleAnswer||ch.placeholder||ch.hint||'';
}
function challengeExplanation(s){
  if(!s)return '';
  if(s.isINPUT)return t('explain.input');
  if(s.isKEY)return t('explain.key');
  if(s.isARK)return t('explain.ark');
  if(s.isSUB)return t('explain.sub');
  if(s.isSH)return t('explain.shift');
  if(s.isMX)return t('explain.mix');
  if(s.schemeStep)return t('explain.scheme');
  if(s.outputStep)return t('explain.output');
  return s.why||'';
}
function writeChallengeExplanation(s,prefix=''){
  const box=document.getElementById('challenge-explain');if(!box)return;
  const answer=challengeAnswerText(s);
  box.innerHTML=`${prefix?`<div class="challenge-reveal-note">${escHtml(prefix)}</div>`:''}<div><strong>${t('student.answer')}:</strong> <span class="vout">${escHtml(answer)}</span></div><div><strong>${t('student.explanation')}:</strong> ${escHtml(challengeExplanation(s))}</div>`;
  box.classList.add('show');
}
function showStepAnswer(){
  const s=steps[curIdx];if(!s||!s.challenge)return;
  const input=document.getElementById('step-answer'),btn=document.getElementById('step-answer-btn'),fb=document.getElementById('challenge-feedback');
  const answer=challengeAnswerText(s);
  if(input){
    input.value=answer;
    input.classList.add('ok');
    input.classList.remove('no');
  }
  if(btn)btn.style.display='inline-flex';
  if(fb)fb.textContent=t('student.revealed');
  solvedChallenges.add(curIdx);
  writeChallengeExplanation(s,t('student.revealed'));
  updateScoreHud();
  syncResultPanel();
}

function updateRoundDetail(s,idx,rel=relatedCells(s,idx,'after')){
  document.querySelectorAll('[data-rd-before],[data-rd-after]').forEach(el=>el.classList.remove('active','source','target','column-source'));
  rel.source.forEach(i=>{const before=document.querySelector(`[data-rd-before="${i}"]`);if(before)before.classList.add(s.isMX?'column-source':'source','active');});
  rel.target.forEach(i=>{const after=document.querySelector(`[data-rd-after="${i}"]`);if(after)after.classList.add('target','active');});
  const active=document.getElementById('rd-active');
  if(active)active.textContent=matrixChangeText(s,rel);
  const flow=document.getElementById('rd-bitflow');
  if(flow){
    const targetIdx=rel.targetIdx,bv=s.isSH?s.before[rel.sourceIdx]:s.before[targetIdx],av=s.after[targetIdx],kv=keyByteFor(s,targetIdx);
    const bits=n=>B8(n).split('').map(bit=>`<span>${bit}</span>`).join('');
    if(s.isARK)flow.innerHTML=`<div><b>State</b><div class="bit-row">${bits(bv)}</div></div><strong>xor</strong><div><b>Key</b><div class="bit-row keybits">${bits(kv)}</div></div><strong>=</strong><div><b>Result</b><div class="bit-row outbits">${bits(av)}</div></div>`;
    else if(s.isSUB){const hx=H(bv);flow.innerHTML=`<div><b>Input byte</b><div class="bit-row">${bits(bv)}</div></div><strong>S-Box row ${hx[0]} col ${hx[1]}</strong><div><b>Output byte</b><div class="bit-row outbits">${bits(av)}</div></div>`;}
    else if(s.isSH){flow.innerHTML=`<div><b>Before [${rel.sourceIdx}]</b><div class="bit-row">${bits(bv)}</div></div><strong>row ${rel.row} shift</strong><div><b>After [${targetIdx}]</b><div class="bit-row outbits">${bits(av)}</div></div>`;}
    else if(s.isMX){flow.innerHTML=`<div><b>Column ${rel.col} input</b><div class="mix-chip-row">${rel.source.map(i=>`<span>${H(s.before[i])}</span>`).join('')}</div></div><strong>GF mix</strong><div><b>Output [${targetIdx}]</b><div class="bit-row outbits">${bits(av)}</div></div>`;}
    else flow.innerHTML=`<div><b>Input</b><div class="bit-row">${bits(bv)}</div></div><strong>-></strong><div><b>Output</b><div class="bit-row outbits">${bits(av)}</div></div>`;
  }
}

function checkStepAnswer(){
  const s=steps[curIdx];if(!s||!s.challenge)return true;
  const input=document.getElementById('step-answer'),fb=document.getElementById('challenge-feedback');
  const ch=s.challenge;
  const raw=(input?input.value:'').trim();
  const value=raw.toUpperCase();
  const usedOverride=raw.toLowerCase()===CHECK_OVERRIDE;
  let ok=usedOverride;
  if(!ok&&ch.kind==='text'){
    const low=raw.toLowerCase();
    ok=(ch.contains||[]).every(word=>low.includes(word.toLowerCase()));
    if(!ok&&ch.minLen)ok=raw.length>=ch.minLen;
  }else if(!ok&&ch.kind==='choice'){
    ok=raw===ch.answer;
  }else if(!ok){
    ok=value===String(ch.answer).toUpperCase();
  }
  if(input){input.classList.toggle('ok',ok);input.classList.toggle('no',!ok);}
  if(ok){
    if(!scoredChallenges.has(curIdx)){
      practiceScore+=30;
      scoredChallenges.add(curIdx);
    }
    if(fb)fb.textContent=`${t('student.correct')} ${t('score.correctDelta')}`;
    solvedChallenges.add(curIdx);
    writeChallengeExplanation(s);
  }else{
    const tries=(challengeAttempts.get(curIdx)||0)+1;
    challengeAttempts.set(curIdx,tries);
    practiceScore-=10;
    if(fb)fb.textContent=`${t('student.wrong',{n:tries,hint:s.challenge.hint})} ${t('score.incorrectDelta')}`;
    if(tries>=3){showStepAnswer();return true;}
    else{
      const btn=document.getElementById('step-answer-btn');
      if(btn)btn.style.display='none';
      const box=document.getElementById('challenge-explain');
      if(box){box.innerHTML='';box.classList.remove('show');}
    }
  }
  updateScoreHud();
  syncResultPanel();
  return ok;
}

function canLeaveCurrentStep(){
  const s=steps[curIdx];
  if(!s||!s.challenge||solvedChallenges.has(curIdx))return true;
  return checkStepAnswer();
}

function buildGrid(s,gen=renderGen){
  const beforeGrid=document.getElementById('sc-grid-before'),afterGrid=document.getElementById('sc-grid-after'),keyGrid=document.getElementById('sc-grid-key');
  if(!beforeGrid||!afterGrid)return;
  beforeGrid.innerHTML='';afterGrid.innerHTML='';if(keyGrid)keyGrid.innerHTML='';
  const order=orderedStepIndices(s);
  order.forEach(idx=>{
    const beforeCell=document.createElement('div');
    beforeCell.className='scell matrix-cell before-cell';
    beforeCell.id=`scb${idx}`;
    beforeCell.dataset.matrixSide='before';
    beforeCell.dataset.idx=idx;
    setMatrixCellContent(beforeCell,s,idx,'before');
    beforeCell.onmouseenter=()=>{const target=highlightCell(s,idx,'before');showCellDetail(s,target,'after');};
    beforeCell.onclick=()=>{clearTimeout(animT);const target=highlightCell(s,idx,'before');showCellDetail(s,target,'after');};
    beforeGrid.appendChild(beforeCell);

    if(keyGrid&&s.isARK){
      const keyCell=document.createElement('div');
      keyCell.className='scell matrix-cell key-cell';
      keyCell.id=`sck${idx}`;
      keyCell.dataset.matrixSide='key';
      keyCell.dataset.idx=idx;
      keyCell.innerHTML=`<span>${H(keyByteFor(s,idx))}</span><small>[${idx}]</small>`;
      keyCell.onmouseenter=()=>{highlightCell(s,idx,'after');showCellDetail(s,idx,'after');};
      keyCell.onclick=()=>{clearTimeout(animT);highlightCell(s,idx,'after');showCellDetail(s,idx,'after');};
      keyGrid.appendChild(keyCell);
    }

    const afterCell=document.createElement('div');
    afterCell.className=`scell matrix-cell after-cell pending ${s.dc||''}`;
    afterCell.id=`sca${idx}`;
    afterCell.dataset.matrixSide='after';
    afterCell.dataset.idx=idx;
    setMatrixCellContent(afterCell,s,idx,'after');
    afterCell.onmouseenter=()=>{highlightCell(s,idx,'after');showCellDetail(s,idx,'after');};
    afterCell.onclick=()=>{clearTimeout(animT);highlightCell(s,idx,'after');showCellDetail(s,idx,'after');};
    afterGrid.appendChild(afterCell);
  });
  showCellDetail(s,order[0]||0,'after');
  highlightCell(s,order[0]||0,'after');
  let i=0;
  function nx(){
    if(gen!==renderGen)return;
    if(i<order.length){
      const idx=order[i],cell=document.getElementById(`sca${idx}`);
      if(cell){
        cell.classList.remove('pending',s.dc);
        cell.classList.add('revealed',s.sc);
      }
      highlightCell(s,idx,'after');showCellDetail(s,idx,'after');
      i++;animT=setTimeout(nx,animDelay(170));
    }else{
      document.querySelectorAll('#sc-grid-after .after-cell').forEach(cell=>{cell.classList.remove('pending',s.sc);cell.classList.add('revealed',s.dc);});
      const et=document.getElementById('sc-et');if(et)et.textContent='Hover or click any byte for the calculation';
    }
  }
  animT=setTimeout(nx,animDelay(120));
}

function stepNav(dir){
  stopPlay();
  const n=curIdx+dir;
  if(n<0)return;
  if(dir>0&&!canLeaveCurrentStep())return;
  if(n>=steps.length){navigateToStage('result');return;}
  curIdx=n;renderStep(curIdx);
}
function togglePlay(){
  stopPlay();
  alert(t('alert.autoplay'));
}
function sched(){
  clearTimeout(playTimer);
  if(!isPlaying||curIdx>=steps.length-1){stopPlay();return;}
  playTimer=setTimeout(()=>{if(!isPlaying)return;curIdx++;renderStep(curIdx);sched();},playSp);
}
function stopPlay(){
  isPlaying=false;clearTimeout(playTimer);
  const play=document.getElementById('btnplay'),stop=document.getElementById('btnstop');
  if(play)play.textContent='Play';if(stop)stop.disabled=true;
}

function clrAll(){
  stopPlay();
  ['pIn','kIn'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('player').style.display='none';
  document.getElementById('out-blk').classList.remove('show');
  document.getElementById('dec-box').style.display='none';
  document.getElementById('ftrack').innerHTML='';
  document.getElementById('scard').innerHTML=`<div style="text-align:center;padding:38px;color:var(--muted);font-family:'Fraunces',serif;font-size:1rem">${t('flow.empty.html')}</div>`;
  const result=document.getElementById('result-cipher');if(result)result.textContent=t('result.none');
  const resultSummary=document.getElementById('result-practice-summary');if(resultSummary)resultSummary.innerHTML='';
  const resultBox=document.getElementById('result-dec-box');if(resultBox)resultBox.style.display='none';
  lastCipher=null;steps=[];solvedChallenges.clear();resetPracticeScore();encryptionComplete=false;celebrationShown=false;syncAesCalculator();
}

function buildSteps(plain,kb){
  const out=[],pb=plain.split('').map(c=>c.charCodeAt(0)),padded=pad16([...pb]),block=padded.slice(0,16),w=kx(kb);
  const add=(o)=>out.push(Object.assign({bc:'st',sc:'sct',dc:'dnt',mapPos:0,layout:'col'},o));
  const roundKey=(r)=>[...Array(4)].flatMap((_,c)=>[...Array(4)].map((_,row)=>w[r*4+c][row]));
  const cipher=encFull(plain,kb).slice(0,16);
  const q=(salt,max)=>(cipher[salt%16]^kb[(salt*7)%kb.length]^block[(salt*3)%16])%max;
  const qArk=q(4,16),qSub=q(5,16),qShiftSrcCol=q(6,4),qMix=q(7,16),qArk1=q(8,16);

  const inputChars=Array.from({length:16},(_,i)=>i<pb.length?plain[i]:'pad');
  add({badge:t('step.input.badge'),title:t('step.input.title'),why:t('step.input.why'),leftLabel:t('step.input.left'),glbl:t('step.input.out'),before:block,after:block,beforeChars:inputChars,isINPUT:true,mapPos:0,
    challenge:{kind:'text',prompt:t('step.input.prompt'),contains:['character','ascii','hex'],minLen:12,placeholder:t('step.input.placeholder'),hint:t('step.input.hint'),sampleAnswer:t('step.input.sample')}});

  const keyChars=kb.slice(0,16).map(b=>String.fromCharCode(b));
  add({badge:t('step.key.badge'),bc:'sd2',sc:'scd',dc:'dnd',title:t('step.key.title'),why:t('step.key.why'),leftLabel:t('step.key.left'),glbl:t('step.key.out'),before:kb.slice(0,16),after:kb.slice(0,16),beforeChars:keyChars,isKEY:true,mapPos:1,
    challenge:{kind:'text',prompt:t('step.key.prompt'),contains:['32','256'],minLen:10,placeholder:t('step.key.placeholder'),hint:t('step.key.hint'),sampleAnswer:t('step.key.sample')}});

  let state=block.slice();
  let rk=roundKey(0),before=state.slice();state=state.map((b,i)=>b^rk[i]);
  add({badge:t('step.ark0.badge'),title:t('step.ark0.title'),why:t('step.ark0.why'),glbl:t('step.ark0.out'),before,after:state.slice(),isARK:true,roundKey:rk.slice(),et:t('step.ark0.detail'),fm:`Byte 0: 0x${H(before[0])} XOR 0x${H(rk[0])} = 0x${H(state[0])}`,mapPos:1,
    challenge:{prompt:t('step.ark0.prompt',{idx:qArk}),answer:H(state[qArk]),hint:t('step.ark0.hint')}});

  let st=ts(state);
  before=fs(cS(st));for(let r=0;r<4;r++)for(let c=0;c<4;c++)st[r][c]=SB[st[r][c]];
  let after=fs(cS(st));
  add({badge:t('step.sub.badge'),bc:'so',sc:'sco',dc:'dno',title:t('step.sub.title'),why:t('step.sub.why'),glbl:t('step.sub.out'),before,after,isSUB:true,et:t('step.sub.detail'),fm:`Byte 0: S-Box[0x${H(before[0])}] = 0x${H(after[0])}`,showSboxHint:true,mapPos:2,
    challenge:{prompt:t('step.sub.prompt',{idx:qSub}),answer:H(after[qSub]),hint:t('step.sub.hint')}});

  before=rowMajorFromState(st);for(let r=1;r<4;r++){const row=st[r].slice();for(let c=0;c<4;c++)st[r][c]=row[(c+r)%4];}
  after=rowMajorFromState(st);
  const qShiftAnswerCol=(qShiftSrcCol+3)%4;
  add({badge:t('step.shift.badge'),bc:'sg',sc:'scg',dc:'dng',title:t('step.shift.title'),why:t('step.shift.why'),glbl:t('step.shift.out'),before,after,isSH:true,layout:'row',et:t('step.shift.detail'),fm:[0,1,2,3].map(r=>`Row ${r}: ${[0,1,2,3].map(c=>H(before[r*4+c])).join(' ')} -> ${[0,1,2,3].map(c=>H(after[r*4+c])).join(' ')}`).join('<br>'),mapPos:3,
    challenge:{max:1,prompt:t('step.shift.prompt',{col:qShiftSrcCol}),answer:String(qShiftAnswerCol),hint:t('step.shift.hint')}});

  before=fs(cS(st));for(let c=0;c<4;c++){const[a,b,d,e]=[st[0][c],st[1][c],st[2][c],st[3][c]];st[0][c]=gm(2,a)^gm(3,b)^d^e;st[1][c]=a^gm(2,b)^gm(3,d)^e;st[2][c]=a^b^gm(2,d)^gm(3,e);st[3][c]=gm(3,a)^b^d^gm(2,e);}
  after=fs(cS(st));
  const mixCoeff=['2311','1231','1123','3112'][qMix%4];
  add({badge:t('step.mix.badge'),bc:'sp',sc:'scp',dc:'dnp',title:t('step.mix.title'),why:t('step.mix.why'),glbl:t('step.mix.out'),before,after,isMX:true,et:t('step.mix.detail'),fm:`Column 0 output byte 0 = 0x${H(after[0])}`,mapPos:4,
    challenge:{max:4,prompt:t('step.mix.prompt',{idx:qMix}),answer:mixCoeff,hint:t('step.mix.hint')}});

  before=fs(cS(st));rk=roundKey(1);for(let c=0;c<4;c++)for(let r=0;r<4;r++)st[r][c]^=w[4+c][r];
  after=fs(cS(st));
  add({badge:t('step.ark1.badge'),title:t('step.ark1.title'),why:t('step.ark1.why'),glbl:t('step.ark1.out'),before,after,isARK:true,roundKey:rk.slice(),et:t('step.ark1.detail'),fm:`Round key 1: ${hA(rk)}`,mapPos:5,
    challenge:{prompt:t('step.ark1.prompt',{idx:qArk1}),answer:H(after[qArk1]),hint:t('step.ark1.hint')}});

  add({badge:t('step.scheme.badge'),bc:'sk',sc:'scp',dc:'dnp',title:t('step.scheme.title'),why:t('step.scheme.why'),before:after,after:after,schemeStep:true,mapPos:6,
    challenge:{kind:'text',prompt:t('step.scheme.prompt'),contains:['mix'],placeholder:t('step.scheme.placeholder'),hint:t('step.scheme.hint'),sampleAnswer:t('step.scheme.sample')}});

  add({badge:t('step.output.badge'),title:t('step.output.title'),why:t('step.output.why'),glbl:t('step.output.out'),before:cipher,after:cipher,outputStep:true,mapPos:7});
  return out;
}

loadSettings();
createResultSection();
createStageControls();
createSideTools();
createAesMapModal();
createFinishCelebration();
createSettingsPanel();
applySettings();
navigateToStage('main');
