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
function ksS(i,el){document.querySelectorAll('#kspl .kb').forEach(b=>b.classList.remove('active'));el.classList.add('active');const ex=document.getElementById('ksex');ex.style.opacity='0';setTimeout(()=>{ex.innerHTML=kst[i];ex.style.opacity='1';},150);}

// ------------------------------------------
// ROUND ANIMATION
// ------------------------------------------
function animRounds(){const rc=document.getElementById('rchips');rc.innerHTML='';const chips=[];for(let i=0;i<=14;i++){const c=document.createElement('span');c.className='rchip';c.textContent=i===0?'Init':`R${i}`;if(i===14)c.classList.add('sp');rc.appendChild(c);chips.push(c);}let i=0;function tk(){if(i<chips.length){chips[i].classList.add('lit');i++;setTimeout(tk,200);}}tk();}

// ------------------------------------------
// S-BOX TABLE
// ------------------------------------------
function buildFullSbox(){
  const t=document.getElementById('sboxt-full');
  const hr=document.createElement('tr');hr.appendChild(Object.assign(document.createElement('th'),{textContent:''}));
  for(let c=0;c<16;c++){const th=document.createElement('th');th.textContent='x'+c.toString(16).toUpperCase();hr.appendChild(th);}t.appendChild(hr);
  for(let row=0;row<16;row++){const tr=document.createElement('tr');const th=document.createElement('th');th.textContent=row.toString(16).toUpperCase()+'x';tr.appendChild(th);for(let col=0;col<16;col++){const td=document.createElement('td');const v=SB[row*16+col];td.textContent=v.toString(16).toUpperCase().padStart(2,'0');td.title=`0x${(row*16+col).toString(16).toUpperCase().padStart(2,'0')} -> 0x${v.toString(16).toUpperCase().padStart(2,'0')}`;tr.appendChild(td);}t.appendChild(tr);}
}

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

  // Step 1 Padding
  const pv=16-pb.length;
  out.push({badge:'Padding PKCS#7',bc:'st',sc:'sct',dc:'dnt',title:'PKCS#7 Padding',why:'AES needs exactly 16 bytes (128 bits) per block. PKCS#7 pads the remainder: each padding byte has the value equal to the count of padding bytes added. Example: if 2 bytes missing, add two 0x02 bytes.',glbl:'Block after padding',before:block,after:block,
    et:'Padding formula',fm:`<span class="lbl">Message length: </span><span class="vin">${pb.length} bytes</span><br><span class="lbl">Block size:     </span><span class="vop">16 bytes</span><br><span class="lbl">Missing:        </span><span class="vop">${pv} bytes</span><br><span class="sep"></span><span class="lbl">Pad value = </span><span class="vout">0x${H(pv)}</span><span class="lbl"> (= ${pv} in decimal)</span><br><span class="lbl">Added ${pv} bytes, each = </span><span class="vout">0x${H(pv)}</span><br><span class="sep"></span><span class="lbl">Block: </span><span class="vout">${hA(block)}</span>`});

  // Step 2 Key
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
  showCellDetail(s,0);
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

function highlightCell(s,idx){
  for(let i=0;i<16;i++){const c=document.getElementById(`sc${i}`);if(!c)continue;if(i<idx){c.className=`scell ${s.dc}`;c.innerHTML=`<span>${H(s.after[i])}</span><small>[${i}]</small>`;}else if(i===idx){c.className=`scell ${s.sc}`;if(s.before[i]!==s.after[i])c.innerHTML=`<span class="cf">${H(s.before[i])}</span><span class="ca"> ${H(s.after[i])}</span>`;else c.innerHTML=`<span>${H(s.after[i])}</span><small>[${i}]</small>`;}else{c.className='scell dim';c.innerHTML=`<span>${H(s.before[i])}</span><small>[${i}]</small>`;}}
}

function showCellDetail(s,idx){
  const et=document.getElementById('sc-et'),fm=document.getElementById('sc-fm');if(!et||!fm)return;
  const bv=s.before[idx],av=s.after[idx];
  if(s.isARK){
    const kv=bv^av,bvb=B8(bv),kvb=B8(kv),rvb=B8(av);
    let bc='';for(let bit=7;bit>=0;bit--){const ba=(bv>>bit)&1,bk=(kv>>bit)&1,br=(av>>bit)&1;bc+=`<td class="${ba===bk?'xsm':'xd'}">${ba} XOR ${bk}=${br}</td>`;}
    et.textContent=`Byte [${idx}] - XOR`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--XOR--></span><span class="ch-t">${H(av)}</span></div><div style="overflow-x:auto"><table class="xort"><tr><td class="xlbl">State</td>${[...bvb].map(b=>`<td class="xs">${b}</td>`).join('')}<td class="xlbl" style="padding-left:6px">0x${H(bv)}</td></tr><tr><td class="xlbl">Key</td>${[...kvb].map(b=>`<td class="xk">${b}</td>`).join('')}<td class="xlbl" style="padding-left:6px">0x${H(kv)}</td></tr><tr><td class="xlbl">Rule</td>${bc}<td class="xlbl" style="padding-left:6px;font-size:.58rem">!=->1,=->0</td></tr><tr><td class="xlbl">Result</td>${[...rvb].map(b=>`<td class="xr">${b}</td>`).join('')}<td class="xlbl" style="padding-left:6px">0x${H(av)}</td></tr></table></div><span class="sep"></span><span class="vin">0x${H(bv)}</span> XOR <span class="vkey">0x${H(kv)}</span> = <span class="vout">0x${H(av)}</span>&nbsp;&nbsp;<span class="lbl">encrypt</span><br><span class="vout">0x${H(av)}</span> XOR <span class="vkey">0x${H(kv)}</span> = <span class="vin">0x${H(bv)}</span>&nbsp;&nbsp;<span class="lbl">decrypt (same op!)</span>`;
    return;
  }
  if(s.isSUB){
    const row=bv>>4,col=bv&0xf;
    et.textContent=`Byte [${idx}] - S-Box lookup`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--S-Box--></span><span class="ch-t">${H(av)}</span></div><span class="lbl">Input: </span><span class="vin">0x${H(bv)} = ${B8(bv)}</span><br><div class="nb-row2"><div class="nb2 nhi"><div class="nbl2" style="color:var(--ora)">High nibble</div><div class="nbv2" style="color:var(--ora)">${row}</div><div class="nbs">-> Row ${row}</div></div><div class="nb2 nlo"><div class="nbl2" style="color:var(--pur)">Low nibble</div><div class="nbv2" style="color:var(--pur)">${col}</div><div class="nbs">-> Col ${col}</div></div></div><span class="lbl">S-Box[${row}][${col}] = </span><span class="vout">0x${H(av)}</span>`;
    return;
  }
  if(s.isSH){
    const rowN=Math.floor(idx/4),colN=idx%4,srcCol=(colN+rowN)%4;
    et.textContent=`Byte [${idx}] - Row ${rowN} shift`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--shift ${rowN}--></span><span class="ch-t">${H(av)}</span></div><span class="lbl">Row ${rowN} shifts left by ${rowN}</span><br><span class="lbl">Col ${colN} <- col ${srcCol} (value </span><span class="vin">0x${H(s.before[rowN*4+srcCol])}</span><span class="lbl">)</span><br><span class="sep"></span><span class="lbl">Before: </span><span class="vin">${[0,1,2,3].map(c=>H(s.before[rowN*4+c])).join(' ')}</span><br><span class="lbl">After:  </span><span class="vout">${[0,1,2,3].map(c=>H(s.after[rowN*4+c])).join(' ')}</span>`;
    return;
  }
  if(s.isMX){
    const colN=idx%4,rowO=Math.floor(idx/4);const colIn=[0,1,2,3].map(r=>s.before[r*4+colN]);const cf=[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]][rowO];
    et.textContent=`Byte [${idx}] - Column ${colN} mix`;
    fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--GF(2^8)--></span><span class="ch-t">${H(av)}</span></div><span class="lbl">Col ${colN}: </span><span class="vin">${colIn.map(H).join(' ')}</span><br><span class="lbl">Row ${rowO}: ${cf[0]}.a0 XOR ${cf[1]}.a1 XOR ${cf[2]}.a2 XOR ${cf[3]}.a3</span><br><span class="sep"></span>${cf.map((c,j)=>`<span class="vop">${c}.${H(colIn[j])}=${H(gm(c,colIn[j]))}</span>`).join('<br>')}<br><span class="sep"></span><span class="lbl">XOR all = </span><span class="vout">${H(av)}</span>`;
    return;
  }
  et.textContent=`Byte [${idx}]`;
  fm.innerHTML=`<div class="ch"><span class="ch-f">${H(bv)}</span><span class="ch-a">--></span><span class="ch-t">${H(av)}</span></div>${s.fm}`;
}

function stepNav(dir){stopPlay();const n=curIdx+dir;if(n<0||n>=steps.length)return;curIdx=n;renderStep(curIdx);}
function togglePlay(){if(isPlaying)stopPlay();else{if(curIdx>=steps.length-1)return;isPlaying=true;document.getElementById('btnplay').textContent='Pause';document.getElementById('btnstop').disabled=false;sched();}}
function sched(){if(!isPlaying||curIdx>=steps.length-1){stopPlay();return;}playTimer=setTimeout(()=>{curIdx++;renderStep(curIdx);sched();},playSp);}
function stopPlay(){isPlaying=false;clearTimeout(playTimer);document.getElementById('btnplay').textContent='Play';document.getElementById('btnstop').disabled=true;}
function setSp(ms,el){playSp=ms;document.querySelectorAll('.spb').forEach(b=>b.classList.remove('on'));el.classList.add('on');}
function runDec(){if(!lastCipher){alert('Encrypt first.');return;}const kb=getKey();const r=decFull(lastCipher,kb);document.getElementById('dec-box').style.display='block';document.getElementById('dec-txt').textContent=`"${r}"`;}
function clrAll(){stopPlay();['pIn','kIn'].forEach(id=>document.getElementById(id).value='');document.getElementById('player').style.display='none';document.getElementById('out-blk').classList.remove('show');document.getElementById('dec-box').style.display='none';document.getElementById('ftrack').innerHTML='';document.getElementById('scard').innerHTML='<div style="text-align:center;padding:38px;color:var(--muted);font-family:\'Fraunces\',serif;font-size:1rem">Enter text and press <strong>Encrypt</strong>.</div>';lastCipher=null;steps=[];}
function rndKey(){const ch='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$';let k='';for(let i=0;i<32;i++)k+=ch[Math.floor(Math.random()*ch.length)];document.getElementById('kIn').value=k;syncAesCalculator();}

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
  {id:'result',label:'Result',sections:['result-sec','team'],note:'Final ciphertext check, decrypt check, and project team.'}
];
let activeCourseStage=0;
let renderGen=0;
const solvedChallenges=new Set();
let encryptionComplete=false;
const calcHistory=[];
let calcValue='0',calcStored=null,calcOp=null,calcReset=false;

function hexCompact(bytes){
  return bytes.map(H).join('').toLowerCase();
}

function createResultSection(){
  if(document.getElementById('result-sec'))return;
  const sec=document.createElement('section');
  sec.className='result-sec';
  sec.id='result-sec';
  sec.innerHTML=`<div class="sec">
    <div class="stag fi">Result Check</div>
    <h2 class="sh fi">Check the Encryption Result</h2>
    <p class="sd fi">Use this final stage to verify the ciphertext produced in Practice. Students stay inside the site and can decrypt with the same AES-256 key.</p>
    <div class="flow-inp fi">
      <div class="fi-title">Latest AES-256 Output</div>
      <div class="fi-sub">The result updates after you run encryption in the Practice stage.</div>
      <div class="out-val" id="result-cipher">No ciphertext yet.</div>
      <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-p" onclick="navigateToStage('encrypt')">Back to Practice</button>
        <button class="btn-o" onclick="runDec();syncResultPanel()">Decrypt Check</button>
        <button class="btn-o" onclick="openAesMap()">Open AES Map</button>
      </div>
      <div class="dec-box" id="result-dec-box" style="display:none"><strong>Decrypted:</strong> <span id="result-dec-txt">-</span></div>
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
  bar.innerHTML=`<button class="stage-arrow" onclick="prevStage()">Prev</button>
    <div class="stage-menu-wrap">
      <button class="stage-menu-toggle" id="stage-menu-toggle" onclick="toggleStageMenu()">Stages</button>
      <div class="stage-menu" id="stage-menu">
        ${COURSE_STAGES.map((s,i)=>`<button data-stage-btn="${s.id}" onclick="navigateToStage('${s.id}');closeStageMenu()">${i+1}. ${s.label}</button>`).join('')}
      </div>
    </div>
    <button class="stage-map-btn" onclick="openAesMap()">AES Map</button>
    <button class="stage-arrow" onclick="nextStage()">Next</button>`;
  document.body.appendChild(bar);
}

function toggleStageMenu(){const bar=document.getElementById('stagebar');if(bar)bar.classList.toggle('open');}
function closeStageMenu(){const bar=document.getElementById('stagebar');if(bar)bar.classList.remove('open');}

function createSideTools(){
  if(document.getElementById('tool-left'))return;
  const left=document.createElement('aside');
  left.className='stage-tools left';
  left.id='tool-left';
  left.innerHTML=`<div class="tool-title">AES Calculator</div>
    <div class="aes-calc">
      <div class="calc-top"><span>Standard</span><button type="button" onclick="syncAesCalculator()">AES</button></div>
      <div class="calc-sub" id="calc-mini">Ready for AES byte math</div>
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
    <div class="tool-card"><label>AES quick values</label><div class="tool-result" id="aes-calc-info">Key: 32 chars = 256 bits</div></div>
    <div class="tool-card"><label>History</label><div class="calc-history" id="calc-history"></div></div>
    <div class="tool-card"><label>ASCII table</label><div class="mini-ref" id="tool-ascii-table"></div></div>
    <div class="tool-card"><label>Full S-Box</label><div class="mini-ref sbox-ref" id="tool-sbox-table"></div></div>`;
  const right=document.createElement('aside');
  right.className='stage-tools right';
  right.id='tool-right';
  right.innerHTML=`<div class="tool-title">Current AES Step</div>
    <p class="tool-note" id="stage-note">Use Next to move through the AES course.</p>
    <div class="tool-card"><label>Theory card</label><p class="tool-note">AES-256 uses a 128-bit block, a 256-bit key, ECB mode here, PKCS#7 padding, and HEX output.</p></div>
    <div class="tool-card"><label>Practice rule</label><p class="tool-note">Tools on the left only help calculate. The encrypted result is produced by the AES practice flow after all checks are finished.</p></div>
    <ol class="tool-list">
      <li>Text becomes bytes.</li>
      <li>Bytes fill a 4x4 state matrix.</li>
      <li>Round keys come from the 32-byte key.</li>
      <li>Rounds repeat SubBytes, ShiftRows, MixColumns, AddRoundKey.</li>
      <li>Final round skips MixColumns.</li>
    </ol>`;
  document.body.append(left,right);
  ['pIn','kIn'].forEach(id=>{const el=document.getElementById(id);if(el)el.addEventListener('input',syncAesCalculator);});
  syncAesCalculator();
  updateCalcDisplay();
  renderCalcHistory();
  buildToolReferenceTables();
}

function formatCalc(n){
  if(!isFinite(n))return 'Error';
  const fixed=Number(n.toFixed(10));
  return String(fixed);
}
function updateCalcDisplay(){
  const out=document.getElementById('calc-result');if(out)out.textContent=calcValue;
  const mini=document.getElementById('calc-mini');if(mini)mini.textContent=calcStored!==null&&calcOp?`${formatCalc(calcStored)} ${calcOp}`:'Ready for AES byte math';
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
  box.textContent=`Text: ${plainLen} chars | Block: 16 bytes | Key: ${keyLen}/32 chars = ${keyLen*8} bits`;
}

function renderCalcHistory(){
  const box=document.getElementById('calc-history');if(!box)return;
  box.innerHTML=calcHistory.map(x=>`<div class="history-item">${escHtml(x)}</div>`).join('')||'<div class="history-item">No calculations yet.</div>';
}

function buildToolReferenceTables(){
  const ascii=document.getElementById('tool-ascii-table');
  if(ascii){
    ascii.innerHTML='';
    for(let i=32;i<=126;i++){
      const d=document.createElement('div');
      d.className='mini-cell';
      d.textContent=`${String.fromCharCode(i)} ${H(i)}`;
      ascii.appendChild(d);
    }
  }
  const sbox=document.getElementById('tool-sbox-table');
  if(sbox){
    sbox.innerHTML='';
    for(let i=0;i<256;i++){
      const d=document.createElement('div');
      d.className='mini-cell';
      d.textContent=H(SB[i]);
      d.title=`${H(i)} -> ${H(SB[i])}`;
      sbox.appendChild(d);
    }
  }
}

function createAesMapModal(){
  if(document.getElementById('aes-map-modal'))return;
  const modal=document.createElement('div');
  modal.className='aes-map-modal';
  modal.id='aes-map-modal';
  const nodes=['Plaintext','AddRoundKey 0','SubBytes','ShiftRows','MixColumns','AddRoundKey','Final Round','Ciphertext'];
  modal.innerHTML=`<div class="aes-map-card">
    <div class="aes-map-head"><h3>AES-256 Scheme Map</h3><button onclick="closeAesMap()">Close</button></div>
    <div class="aes-flow-map">${nodes.map((n,i)=>`<div class="aes-node" data-map-pos="${i}">${n}<small>${i===6?'No MixColumns':i===7?'Result':'Step '+(i+1)}</small></div>`).join('')}</div>
    <div class="ibox" style="margin-top:16px">The red marker shows where the student currently is in the AES encryption scheme.</div>
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
  document.querySelectorAll('.aes-node').forEach((node,i)=>{
    node.classList.toggle('done',i<active);
    node.classList.toggle('active',i===active);
  });
}

function navigateToStage(stageId){
  const idx=typeof stageId==='number'?stageId:COURSE_STAGES.findIndex(s=>s.id===stageId);
  if(idx<0)return;
  if(COURSE_STAGES[idx].id==='result'&&!encryptionComplete){
    alert('Finish the AES Practice encryption first. Result opens after the final ciphertext step.');
    closeStageMenu();
    return;
  }
  activeCourseStage=idx;
  const active=COURSE_STAGES[idx];
  const visible=new Set(active.sections);
  document.querySelectorAll('body > section').forEach(sec=>sec.classList.toggle('stage-hidden',!visible.has(sec.id)));
  const footer=document.querySelector('footer');if(footer)footer.style.display=active.id==='result'?'block':'none';
  document.querySelectorAll('.stage-tools').forEach(panel=>{panel.style.display=active.id==='main'?'none':'';});
  document.querySelectorAll('[data-stage-btn]').forEach(btn=>btn.classList.toggle('active',btn.dataset.stageBtn===active.id));
  const toggle=document.getElementById('stage-menu-toggle');if(toggle)toggle.textContent=`${idx+1}. ${active.label}`;
  const note=document.getElementById('stage-note');if(note)note.textContent=active.note;
  document.body.classList.add('stage-app');
  window.scrollTo({top:0,left:0,behavior:'auto'});
  document.querySelectorAll('.fi').forEach(el=>el.classList.add('on'));
  syncResultPanel();
  updateAesMap();
}
function nextStage(){navigateToStage(Math.min(activeCourseStage+1,COURSE_STAGES.length-1));}
function prevStage(){navigateToStage(Math.max(activeCourseStage-1,0));}

document.addEventListener('click',e=>{
  if(!e.target.closest('.stagebar'))closeStageMenu();
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
  if(out)out.textContent=lastCipher?hexCompact(lastCipher):'No ciphertext yet. Run Practice first.';
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
  if(!plain){alert('Enter a message first.');return;}
  if(plain.length>15){alert('For this teaching walkthrough, use up to 15 characters so one padded AES block can be shown in full detail.');return;}
  if(key.length!==32){alert(`AES-256 needs exactly 32 key characters = 256 bits. Current key length: ${key.length}/32.`);return;}
  const kb=getKey();
  solvedChallenges.clear();
  encryptionComplete=false;
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
  alert('Answer each Student Check before moving further.');
}

function renderStep(idx){
  clearTimeout(animT);renderGen++;
  const s=steps[idx];if(!s)return;
  steps.forEach((_,i)=>{const d=document.getElementById(`ftd${i}`);if(!d)return;d.className='ftd'+(i<idx?' done':i===idx?' active':'');if(i>0){const l=document.getElementById(`ftl${i-1}`);if(l)l.className='ftline'+(i<=idx?' done':'');}});
  const card=document.getElementById('scard');if(!card)return;
  card.className='scard active flip';void card.offsetWidth;
  const sbs=document.getElementById('sbox-sec');if(sbs){sbs.style.outline=s.showSboxHint?'3px solid var(--gold)':'';sbs.style.borderRadius=s.showSboxHint?'4px':'';}
  let html=`<div class="sbadge ${s.bc}">${s.badge}</div><div class="stitle">${s.title}</div><div class="swhy">${s.why}</div>`;
  if(s.showAscii)html+=`<div style="position:relative;display:inline-block;margin-bottom:14px"><div class="ascii-hint" onclick="toggleAscii('ap-s','ah-s')">ASCII Table - character reference</div><div class="ascii-pop" id="ap-s"><h4>ASCII Reference</h4><div class="ascii-grid" id="ag-s"></div></div></div>`;
  if(s.showSboxHint)html+=`<div style="margin-bottom:14px;padding:9px 14px;background:#fef5dc;border:2px solid var(--gold);border-radius:9px;font-size:.8rem;color:var(--gold)"><strong>S-Box hint:</strong> high nibble is row, low nibble is column.</div>`;
  html+=`<div class="sbody"><div><div class="sg-lbl" id="sc-lbl">${s.glbl}</div><div class="sgrid" id="sc-grid"></div></div><div class="sexpl"><div class="se-lbl" id="sc-et">${s.et}</div><div class="se-fm" id="sc-fm">${s.fm}</div></div></div>`;
  if(s.challenge)html+=renderChallenge(s.challenge);
  card.innerHTML=html;
  if(s.showAscii)buildAsciiGrid('ag-s');
  buildGrid(s,renderGen);
  document.getElementById('pctr').textContent=`Step ${idx+1} of ${steps.length}`;
  document.getElementById('btnprev').disabled=idx===0;
  document.getElementById('btnnxt').textContent=idx===steps.length-1?'Finish':'Next';
  document.getElementById('btnnxt').disabled=false;
  document.getElementById('pbf').style.width=`${steps.length>1?(idx/(steps.length-1))*100:100}%`;
  if(idx===steps.length-1&&lastCipher){
    encryptionComplete=true;
    document.getElementById('out-blk').classList.add('show');
    document.getElementById('out-val').textContent=hexCompact(lastCipher);
    syncResultPanel();
  }
  updateAesMap(s.mapPos);
}

function renderChallenge(ch){
  let control=`<input id="step-answer" maxlength="${ch.max||2}" placeholder="${ch.placeholder||'??'}" oninput="this.value=this.value.toUpperCase()">`;
  if(ch.kind==='text')control=`<textarea id="step-answer" placeholder="${ch.placeholder||'Write your answer'}"></textarea>`;
  if(ch.kind==='choice')control=`<select id="step-answer" class="challenge-select"><option value="">Choose answer</option>${(ch.options||[]).map(o=>`<option value="${escHtml(o)}">${escHtml(o)}</option>`).join('')}</select>`;
  return `<div class="step-challenge"><h4>Student Check</h4><p>${ch.prompt}</p><div class="challenge-row">${control}<button class="chk-btn" onclick="checkStepAnswer()">Check</button></div><span class="challenge-feedback" id="challenge-feedback">${ch.hint}</span></div>`;
}

function checkStepAnswer(){
  const s=steps[curIdx];if(!s||!s.challenge)return true;
  const input=document.getElementById('step-answer'),fb=document.getElementById('challenge-feedback');
  const ch=s.challenge;
  const raw=(input?input.value:'').trim();
  const value=raw.toUpperCase();
  let ok=false;
  if(ch.kind==='text'){
    const low=raw.toLowerCase();
    ok=(ch.contains||[]).every(word=>low.includes(word.toLowerCase()));
    if(!ok&&ch.minLen)ok=raw.length>=ch.minLen;
  }else if(ch.kind==='choice'){
    ok=raw===ch.answer;
  }else{
    ok=value===String(ch.answer).toUpperCase();
  }
  if(input){input.classList.toggle('ok',ok);input.classList.toggle('no',!ok);}
  if(fb)fb.textContent=ok?'Correct. You can go to the next step.':`Not yet. ${s.challenge.hint}`;
  if(ok)solvedChallenges.add(curIdx);
  return ok;
}

function canLeaveCurrentStep(){
  const s=steps[curIdx];
  if(!s||!s.challenge||solvedChallenges.has(curIdx))return true;
  return checkStepAnswer();
}

function buildGrid(s,gen=renderGen){
  const grid=document.getElementById('sc-grid');if(!grid)return;grid.innerHTML='';
  s.before.forEach((bv,i)=>{
    const c=document.createElement('div');c.className='scell dim';c.id=`sc${i}`;
    c.innerHTML=`<span>${H(bv)}</span><small>[${i}]</small>`;
    c.onclick=()=>{clearTimeout(animT);highlightCell(s,i);showCellDetail(s,i);};
    grid.appendChild(c);
  });
  showCellDetail(s,0);
  let i=0;
  function nx(){
    if(gen!==renderGen)return;
    if(i>0){const pc=document.getElementById(`sc${i-1}`);if(pc){pc.className=`scell ${s.dc}`;pc.innerHTML=`<span>${H(s.after[i-1])}</span><small>[${i-1}]</small>`;}}
    if(i<16){
      const c=document.getElementById(`sc${i}`);
      if(c){c.className=`scell ${s.sc}`;if(s.before[i]!==s.after[i])c.innerHTML=`<span class="cf">${H(s.before[i])}</span><span class="ca"> ${H(s.after[i])}</span>`;else c.innerHTML=`<span>${H(s.after[i])}</span><small>[${i}]</small>`;}
      showCellDetail(s,i);i++;animT=setTimeout(nx,120);
    }else{const fm=document.getElementById('sc-fm');if(fm&&s.fm)fm.innerHTML=s.fm;const et=document.getElementById('sc-et');if(et)et.textContent='All 16 bytes processed';}
  }
  animT=setTimeout(nx,80);
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
  alert('Auto play is disabled for Practice. Solve the Student Check to unlock each next AES step.');
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
  document.getElementById('scard').innerHTML='<div style="text-align:center;padding:38px;color:var(--muted);font-family:\'Fraunces\',serif;font-size:1rem">Enter text and press <strong>Encrypt</strong>.</div>';
  const result=document.getElementById('result-cipher');if(result)result.textContent='No ciphertext yet. Run Practice first.';
  const resultBox=document.getElementById('result-dec-box');if(resultBox)resultBox.style.display='none';
  lastCipher=null;steps=[];solvedChallenges.clear();encryptionComplete=false;syncAesCalculator();
}

function buildSteps(plain,kb){
  const out=[],pb=plain.split('').map(c=>c.charCodeAt(0)),padded=pad16([...pb]),block=padded.slice(0,16),w=kx(kb);
  const add=(o)=>out.push(Object.assign({bc:'st',sc:'sct',dc:'dnt',mapPos:0},o));
  const roundKey=(r)=>[...Array(4)].flatMap((_,c)=>[...Array(4)].map((_,row)=>w[r*4+c][row]));
  const cipher=encFull(plain,kb).slice(0,16);

  add({badge:'Input',title:'Plaintext -> Bytes',why:'AES encrypts bytes. First the text becomes hexadecimal byte values in a 4x4 state matrix.',glbl:'Plaintext block',before:block,after:block,et:'Character conversion',fm:plain.split('').slice(0,16).map((c,i)=>`[${i}] '${c}' = ${c.charCodeAt(0)} = 0x${H(c.charCodeAt(0))}`).join('<br>'),showAscii:true,mapPos:0,
    challenge:{kind:'text',prompt:'Write the rule for converting plaintext into AES bytes.',contains:['ascii','hex'],placeholder:'Example: character -> ASCII -> hex byte',hint:'Mention ASCII and hex bytes.'}});

  const pv=16-pb.length||16;
  add({badge:'Padding',title:'PKCS#7 Padding',why:'AES works on 16-byte blocks. The demo uses one padded block so students can follow every byte.',glbl:'Block after padding',before:block,after:block,et:'Padding detail',fm:`Message length: ${pb.length} bytes<br>Padding value: 0x${H(pv)} repeated ${pv} time(s).`,mapPos:0,
    challenge:{prompt:'What is the padding byte value in hex?',answer:H(pv),hint:'Padding value equals the number of missing bytes.'}});

  add({badge:'Key',bc:'sd2',sc:'scd',dc:'dnd',title:'AES-256 Key Bytes',why:'AES-256 uses exactly 32 key bytes. The first 16 bytes form Round Key 0.',glbl:'First 16 key bytes',before:kb.slice(0,16),after:kb.slice(0,16),et:'Key detail',fm:kb.map((b,i)=>`K[${String(i).padStart(2,'0')}] = 0x${H(b)}`).join('<br>'),mapPos:1,
    challenge:{kind:'choice',prompt:'Which key size is this practice using?',options:['128 bits','192 bits','256 bits','512 bits'],answer:'256 bits',hint:'The entered key is 32 bytes, so AES-256 uses 256 bits.'}});

  let state=block.slice();
  let rk=roundKey(0),before=state.slice();state=state.map((b,i)=>b^rk[i]);
  add({badge:'ARK 0',title:'Round 0 - AddRoundKey',why:'Before Round 1, each state byte is XORed with Round Key 0.',glbl:'State after Round 0 key',before,after:state.slice(),isARK:true,et:'XOR each byte - click a cell',fm:`Byte 0: 0x${H(before[0])} XOR 0x${H(rk[0])} = 0x${H(state[0])}`,mapPos:1,
    challenge:{prompt:`Calculate byte 0: ${H(before[0])} XOR ${H(rk[0])} = ?`,answer:H(state[0]),hint:'Use the XOR tool on the left.'}});

  let st=ts(state);
  before=fs(cS(st));for(let r=0;r<4;r++)for(let c=0;c<4;c++)st[r][c]=SB[st[r][c]];
  let after=fs(cS(st));
  add({badge:'SubBytes',bc:'so',sc:'sco',dc:'dno',title:'Round 1 - SubBytes',why:'Each byte is replaced through the AES S-Box. This is the substitution part of the AES scheme.',glbl:'After SubBytes',before,after,isSUB:true,et:'S-Box lookup - click a byte',fm:`Byte 0: S-Box[0x${H(before[0])}] = 0x${H(after[0])}`,showSboxHint:true,mapPos:2,
    challenge:{prompt:`Use the S-Box: S-Box[${H(before[0])}] = ?`,answer:H(after[0]),hint:'High hex digit is row, low hex digit is column.'}});

  before=rowMajorFromState(st);for(let r=1;r<4;r++){const row=st[r].slice();for(let c=0;c<4;c++)st[r][c]=row[(c+r)%4];}
  after=rowMajorFromState(st);
  add({badge:'ShiftRows',bc:'sg',sc:'scg',dc:'dng',title:'Round 1 - ShiftRows',why:'Rows rotate left by 0, 1, 2, and 3. This moves bytes between columns before MixColumns.',glbl:'After ShiftRows',before,after,isSH:true,et:'Row movement - click a byte',fm:[0,1,2,3].map(r=>`Row ${r}: ${[0,1,2,3].map(c=>H(before[r*4+c])).join(' ')} -> ${[0,1,2,3].map(c=>H(after[r*4+c])).join(' ')}`).join('<br>'),mapPos:3,
    challenge:{prompt:'After shifting row 1 left, what is the first byte of row 1?',answer:H(after[4]),hint:'Row 1 shifts left by one position.'}});

  before=fs(cS(st));for(let c=0;c<4;c++){const[a,b,d,e]=[st[0][c],st[1][c],st[2][c],st[3][c]];st[0][c]=gm(2,a)^gm(3,b)^d^e;st[1][c]=a^gm(2,b)^gm(3,d)^e;st[2][c]=a^b^gm(2,d)^gm(3,e);st[3][c]=gm(3,a)^b^d^gm(2,e);}
  after=fs(cS(st));
  add({badge:'MixColumns',bc:'sp',sc:'scp',dc:'dnp',title:'Round 1 - MixColumns',why:'Each column is mixed in GF(2^8). This is the diffusion part of the AES scheme.',glbl:'After MixColumns',before,after,isMX:true,et:'GF(2^8) calculation - click a byte',fm:`Column 0 output byte 0 = 0x${H(after[0])}`,mapPos:4,
    challenge:{prompt:'Calculate MixColumns output byte 0 for column 0. What hex value appears?',answer:H(after[0]),hint:'Click byte 0 to see the GF(2^8) multiplication details.'}});

  before=fs(cS(st));rk=roundKey(1);for(let c=0;c<4;c++)for(let r=0;r<4;r++)st[r][c]^=w[4+c][r];
  after=fs(cS(st));
  add({badge:'ARK 1',title:'Round 1 - AddRoundKey',why:'Round 1 finishes by XORing the mixed state with Round Key 1.',glbl:'After Round Key 1',before,after,isARK:true,et:'XOR with round key - click a byte',fm:`Round key 1: ${hA(rk)}`,mapPos:5,
    challenge:{prompt:`Calculate byte 0: ${H(before[0])} XOR ${H(rk[0])} = ?`,answer:H(after[0]),hint:'Use the XOR tool or click byte 0 for bit detail.'}});

  add({badge:'Scheme',bc:'sk',sc:'scp',dc:'dnp',title:'AES Scheme Continues',why:'This site teaches one full AES round in detail. AES-256 then repeats the same scheme for Rounds 2-13 and uses a final Round 14 without MixColumns.',glbl:'State after one full round',before:after,after:after,et:'Remaining AES-256 scheme',fm:'Rounds 2-13: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey<br>Round 14: SubBytes -> ShiftRows -> AddRoundKey',mapPos:6,
    challenge:{kind:'text',prompt:'Write which step the final AES round skips.',contains:['mix'],placeholder:'The final round skips...',hint:'Final round has no MixColumns.'}});

  add({badge:'Output',title:'Final Ciphertext',why:'The real AES-256 result is calculated by the full algorithm, while the student walkthrough focuses on one complete round scheme.',glbl:'Ciphertext bytes',before:cipher,after:cipher,et:'Final result',fm:`Ciphertext: <span class="vout">${hexCompact(cipher)}</span>`,mapPos:7});
  return out;
}

createResultSection();
createStageControls();
createSideTools();
createAesMapModal();
navigateToStage('main');
