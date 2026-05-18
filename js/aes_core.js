// ══════════════════════════════════════════
// AES-256 CORE — NIST FIPS-197
// ══════════════════════════════════════════

const SB=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
const ISB=new Array(256);
for(let i=0;i<256;i++) ISB[SB[i]]=i;
const RC=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];

// GF(2^8) helpers
function xt(b){return b&0x80?((b<<1)^0x1b)&0xff:(b<<1)&0xff;}
function gm(a,b){let p=0;for(let i=0;i<8;i++){if(b&1)p^=a;a=xt(a);b>>=1;}return p;}

// Key expansion — generates 60 words (15 round keys × 4 words each)
function kx(key){
  const nk=key.length/4,nr=nk+6,w=[];
  for(let i=0;i<nk;i++) w.push(key.slice(i*4,i*4+4).slice());
  for(let i=nk;i<4*(nr+1);i++){
    let t=w[i-1].slice();
    if(i%nk===0){t=[t[1],t[2],t[3],t[0]].map(b=>SB[b]);t[0]^=RC[i/nk-1];}
    else if(nk>6&&i%nk===4) t=t.map(b=>SB[b]);
    w.push(w[i-nk].map((b,j)=>b^t[j]));
  }
  return w;
}

// State matrix helpers: bytes stored column-major
function ts(bytes){const s=[[],[],[],[]];for(let c=0;c<4;c++)for(let r=0;r<4;r++)s[r][c]=bytes[c*4+r];return s;}
function fs(s){const b=[];for(let c=0;c<4;c++)for(let r=0;r<4;r++)b.push(s[r][c]);return b;}
function cS(s){return s.map(r=>r.slice());}

// PKCS#7 padding
function pad16(b){const p=16-(b.length%16)||16;return b.concat(new Array(p).fill(p));}
function unpad(b){const p=b[b.length-1];return b.slice(0,b.length-p);}

// Formatting utilities
function H(n){return n.toString(16).toUpperCase().padStart(2,'0');}
function hA(a){return a.map(H).join(' ');}
function B8(n){return n.toString(2).padStart(8,'0');}

// Read key from DOM input (or accept raw array)
function getKey(raw){
  if(raw) return raw;
  let k=document.getElementById('kIn').value;
  while(k.length<32) k+='\0';
  return k.slice(0,32).split('').map(c=>c.charCodeAt(0));
}

// Full encrypt — returns byte array of ciphertext
function encFull(plain,kb){
  const nr=14,w=kx(kb),out=[],pd=pad16([...plain.split('').map(c=>c.charCodeAt(0))]);
  for(let b=0;b<pd.length;b+=16){
    const s=ts(pd.slice(b,b+16));
    for(let c=0;c<4;c++) for(let r=0;r<4;r++) s[r][c]^=w[c][r];
    for(let rnd=1;rnd<=nr;rnd++){
      for(let r=0;r<4;r++) for(let c=0;c<4;c++) s[r][c]=SB[s[r][c]];
      for(let r=1;r<4;r++){const row=s[r].slice();for(let c=0;c<4;c++)s[r][c]=row[(c+r)%4];}
      if(rnd<nr){
        for(let c=0;c<4;c++){
          const[a,bv,d,e]=[s[0][c],s[1][c],s[2][c],s[3][c]];
          s[0][c]=gm(2,a)^gm(3,bv)^d^e;s[1][c]=a^gm(2,bv)^gm(3,d)^e;
          s[2][c]=a^bv^gm(2,d)^gm(3,e);s[3][c]=gm(3,a)^bv^d^gm(2,e);
        }
      }
      for(let c=0;c<4;c++) for(let r=0;r<4;r++) s[r][c]^=w[rnd*4+c][r];
    }
    out.push(...fs(s));
  }
  return out;
}

// Full decrypt — returns plaintext string
function decFull(cb,kb){
  const nr=14,w=kx(kb),result=[];
  for(let b=0;b<cb.length;b+=16){
    const s=ts(cb.slice(b,b+16));
    for(let c=0;c<4;c++) for(let r=0;r<4;r++) s[r][c]^=w[nr*4+c][r];
    for(let rnd=nr-1;rnd>=0;rnd--){
      for(let row=1;row<4;row++){const ro=s[row].slice();for(let c=0;c<4;c++)s[row][c]=ro[(c+4-row)%4];}
      for(let row=0;row<4;row++) for(let c=0;c<4;c++) s[row][c]=ISB[s[row][c]];
      for(let c=0;c<4;c++) for(let r=0;r<4;r++) s[r][c]^=w[rnd*4+c][r];
      if(rnd>0){
        for(let c=0;c<4;c++){
          const[a,bv,d,e]=[s[0][c],s[1][c],s[2][c],s[3][c]];
          s[0][c]=gm(0x0e,a)^gm(0x0b,bv)^gm(0x0d,d)^gm(0x09,e);
          s[1][c]=gm(0x09,a)^gm(0x0e,bv)^gm(0x0b,d)^gm(0x0d,e);
          s[2][c]=gm(0x0d,a)^gm(0x09,bv)^gm(0x0e,d)^gm(0x0b,e);
          s[3][c]=gm(0x0b,a)^gm(0x0d,bv)^gm(0x09,d)^gm(0x0e,e);
        }
      }
    }
    result.push(...fs(s));
  }
  return unpad(result).map(b=>String.fromCharCode(b)).join('');
}

// ══════════════════════════════════════════
// STEP BUILDER — generates visualization steps
// ══════════════════════════════════════════
// Map step index → AES map position (0-based)
// 0=Plaintext, 1=ARK0, 2=Sub1, 3=Sh1, 4=Mix1, 5=ARK1, 6=Rounds2-14, 7=Cipher
const STEP_MAP_POS=[0,0,0,1,2,3,4,5,6,7];

function buildSteps(plain,kb){
  const out=[],pb=plain.split('').map(c=>c.charCodeAt(0)),
        padded=pad16([...pb]),block=padded.slice(0,16),
        w=kx(kb),nr=14;
  const rk0=[];for(let c=0;c<4;c++)for(let r=0;r<4;r++)rk0.push(w[c][r]);

  // Step 0 Input
  out.push({badge:'Input',bc:'st',sc:'sct',dc:'dnt',title:'Plaintext → Bytes',
    why:'AES processes bytes, not text. Every character is converted to its ASCII numeric code, then expressed in hexadecimal (base 16). This is the raw data entering the 4×4 state matrix.',
    glbl:'Plaintext — 16 bytes',before:block,after:block,
    et:'Each character → ASCII decimal → Hex',
    fm:plain.split('').slice(0,16).map((c,i)=>`<span class="lbl">[${String(i).padStart(2)}] </span><span class="vin">'${c}'</span> → ASCII <span class="vop">${c.charCodeAt(0)}</span> → <span class="vout">${H(c.charCodeAt(0))}</span>`).join('<br>'),
    showAscii:true,mapPos:0});

  // Step 1 Padding
  const pv=16-pb.length;
  out.push({badge:'Padding PKCS#7',bc:'st',sc:'sct',dc:'dnt',title:'PKCS#7 Padding',
    why:'AES needs exactly 16 bytes (128 bits) per block. PKCS#7 pads the remainder: each padding byte has the value equal to the count of padding bytes added.',
    glbl:'Block after padding',before:block,after:block,
    et:'Padding formula',
    fm:`<span class="lbl">Message length: </span><span class="vin">${pb.length} bytes</span><br><span class="lbl">Block size:     </span><span class="vop">16 bytes</span><br><span class="lbl">Missing:        </span><span class="vop">${pv} bytes</span><br><span class="sep"></span><span class="lbl">Pad value = </span><span class="vout">0x${H(pv)}</span><span class="lbl"> (= ${pv} in decimal)</span><br><span class="lbl">Added ${pv} bytes, each = </span><span class="vout">0x${H(pv)}</span>`,mapPos:0});

  // Step 2 Key
  out.push({badge:'Key AES-256',bc:'sd2',sc:'scd',dc:'dnd',title:'Your 256-bit Key → 32 Bytes',
    why:'The 32-byte key feeds the Key Schedule which generates 15 round keys. AES-256 has a unique Extra SubWord step. Changing just one character produces a completely different ciphertext.',
    glbl:'Key — 32 bytes = 256 bits',before:kb.slice(0,16),after:kb.slice(0,16),
    et:'Key bytes (first 16 of 32)',
    fm:kb.slice(0,16).map((b,i)=>{const c=b<32?'\\0':String.fromCharCode(b);return `<span class="lbl">[${String(i).padStart(2)}] </span><span class="vin">'${c}'</span> = <span class="vout">${H(b)}</span>`;}).join('<br>')+`<br><span class="lbl">... + bytes 16–31 (AES-256 needs all 32)</span>`,mapPos:0});

  // Step 3 ARK0 — Initial AddRoundKey
  const after0=block.map((b,i)=>b^rk0[i]);
  out.push({badge:'AddRoundKey Round 0',bc:'st',sc:'sct',dc:'dnt',title:'Initial AddRoundKey — XOR with Key',
    why:'Before any rounds begin, every plaintext byte is XOR-ed with Round Key 0 (your original key). XOR: same bits → 0, different bits → 1. This "initial whitening" means Round 1 already starts on scrambled data.',
    glbl:'State after initial XOR',before:block,after:after0,isARK:true,arkBefore:block,arkKey:rk0,
    et:'XOR for each byte — click any cell',fm:'',mapPos:1});

  let curSt=ts(after0.slice());
  const rkF1=[];for(let c=0;c<4;c++)for(let r=0;r<4;r++)rkF1.push(w[4+c][r]);

  // Step 4 SubBytes R1
  const bSub=fs(cS(curSt)),aSub=bSub.map(b=>SB[b]);
  out.push({badge:'SubBytes Round 1',bc:'so',sc:'sco',dc:'dno',title:'Round 1 — SubBytes',
    why:'Every byte replaced via S-Box lookup. High nibble = row, low nibble = column. This introduces non-linearity — without it AES would be solvable with algebra.',
    glbl:'State after SubBytes',before:bSub,after:aSub,isSUB:true,
    et:'S-Box lookup — click any cell',fm:'',showSboxHint:true,mapPos:2});
  for(let r=0;r<4;r++) for(let c=0;c<4;c++) curSt[r][c]=SB[curSt[r][c]];

  // Step 5 ShiftRows R1
  const bSh=fs(cS(curSt));const stSh=cS(curSt);
  for(let r=1;r<4;r++){const row=stSh[r].slice();for(let c=0;c<4;c++)stSh[r][c]=row[(c+r)%4];}
  const aSh=fs(stSh);
  out.push({badge:'ShiftRows Round 1',bc:'sg',sc:'scg',dc:'dng',title:'Round 1 — ShiftRows',
    why:'Each row rotates left by its row number. Row 0: no shift. Row 1: 1 left. Row 2: 2 left. Row 3: 3 left. Moves bytes into different column positions so MixColumns blends bytes from many original positions.',
    glbl:'State after ShiftRows',before:bSh,after:aSh,isSH:true,
    et:'Row shifts — click any cell',
    fm:[0,1,2,3].map(r=>`<span class="lbl">Row ${r} (shift ${r}): </span><span class="vin">${[0,1,2,3].map(c=>H(bSh[r*4+c])).join(' ')}</span> → <span class="vout">${[0,1,2,3].map(c=>H(aSh[r*4+c])).join(' ')}</span>`).join('<br>'),mapPos:3});
  for(let r=1;r<4;r++){const row=curSt[r].slice();for(let c=0;c<4;c++)curSt[r][c]=row[(c+r)%4];}

  // Step 6 MixColumns R1
  const bMx=fs(cS(curSt));const stMx=cS(curSt);
  for(let c=0;c<4;c++){
    const[a,bv,d,e]=[stMx[0][c],stMx[1][c],stMx[2][c],stMx[3][c]];
    stMx[0][c]=gm(2,a)^gm(3,bv)^d^e;stMx[1][c]=a^gm(2,bv)^gm(3,d)^e;
    stMx[2][c]=a^bv^gm(2,d)^gm(3,e);stMx[3][c]=gm(3,a)^bv^d^gm(2,e);
  }
  const aMx=fs(stMx);
  const col0=[0,1,2,3].map(r=>bMx[r*4]);
  out.push({badge:'MixColumns Round 1',bc:'sp',sc:'scp',dc:'dnp',title:'Round 1 — MixColumns',
    why:'Each column multiplied by a fixed matrix in GF(2⁸). Every output byte depends on all 4 input bytes of its column. Combined with ShiftRows, 2 rounds create full avalanche. Skipped in Round 14.',
    glbl:'State after MixColumns',before:bMx,after:aMx,isMX:true,
    et:'Column 0 — exact calculation',
    fm:`<span class="lbl">Col 0 input: </span><span class="vin">${col0.map(H).join(' ')}</span><br><span class="sep"></span><span class="lbl">out[0] = 2·${H(col0[0])} ⊕ 3·${H(col0[1])} ⊕ ${H(col0[2])} ⊕ ${H(col0[3])}</span><br><span class="lbl">       = </span><span class="vop">${H(gm(2,col0[0]))}</span> ⊕ <span class="vop">${H(gm(3,col0[1]))}</span> ⊕ <span class="vop">${H(col0[2])}</span> ⊕ <span class="vop">${H(col0[3])}</span> = <span class="vout">${H(aMx[0])}</span><br><span class="lbl">Rule: 2·x = shift left + if x≥0x80 XOR 0x1B</span>`,
    mapPos:4});
  for(let c=0;c<4;c++){
    const[a,bv,d,e]=[curSt[0][c],curSt[1][c],curSt[2][c],curSt[3][c]];
    curSt[0][c]=gm(2,a)^gm(3,bv)^d^e;curSt[1][c]=a^gm(2,bv)^gm(3,d)^e;
    curSt[2][c]=a^bv^gm(2,d)^gm(3,e);curSt[3][c]=gm(3,a)^bv^d^gm(2,e);
  }

  // Step 7 ARK1
  const bA1=fs(cS(curSt)),aA1=bA1.map((b,i)=>b^rkF1[i]);
  out.push({badge:'AddRoundKey Round 1',bc:'st',sc:'sct',dc:'dnt',title:'Round 1 — AddRoundKey (XOR Round Key 1)',
    why:'State XOR-ed with Round Key 1. This is where the secret key directly affects the data. Change one bit of the key and the entire output changes.',
    glbl:'State after XOR with Round Key 1',before:bA1,after:aA1,isARK:true,arkBefore:bA1,arkKey:rkF1,
    et:'XOR each byte with round key 1',fm:'',mapPos:5});
  for(let c=0;c<4;c++) for(let r=0;r<4;r++) curSt[r][c]^=w[4+c][r];

  // Step 8 Rounds 2-14
  const stR2=fs(cS(curSt));
  for(let rnd=2;rnd<=nr;rnd++){
    for(let r=0;r<4;r++) for(let c=0;c<4;c++) curSt[r][c]=SB[curSt[r][c]];
    for(let r=1;r<4;r++){const row=curSt[r].slice();for(let c=0;c<4;c++)curSt[r][c]=row[(c+r)%4];}
    if(rnd<nr){
      for(let c=0;c<4;c++){
        const[a,bv,d,e]=[curSt[0][c],curSt[1][c],curSt[2][c],curSt[3][c]];
        curSt[0][c]=gm(2,a)^gm(3,bv)^d^e;curSt[1][c]=a^gm(2,bv)^gm(3,d)^e;
        curSt[2][c]=a^bv^gm(2,d)^gm(3,e);curSt[3][c]=gm(3,a)^bv^d^gm(2,e);
      }
    }
    for(let c=0;c<4;c++) for(let r=0;r<4;r++) curSt[r][c]^=w[rnd*4+c][r];
  }
  const cipher=fs(curSt);
  out.push({badge:'Rounds 2–14',bc:'sk',sc:'scp',dc:'dnp',title:'Rounds 2–14 — AES-256 Completes',
    why:'Rounds 2–13 repeat SubBytes → ShiftRows → MixColumns → AddRoundKey. Round 14 (final) skips MixColumns — intentional for symmetric decryption. 14 rounds total.',
    glbl:`Final state after all 14 rounds`,before:stR2,after:cipher,
    et:'13 more rounds with unique keys',
    fm:`<span class="lbl">Rounds 2–13: SubBytes → ShiftRows → MixColumns → AddRoundKey</span><br><span class="lbl">Round 14:   SubBytes → ShiftRows → AddRoundKey (no MixColumns)</span><br><span class="sep"></span>${Array.from({length:4},(_,i)=>`<span class="lbl">Round Key ${i+2}: </span><span class="vkey">${hA([...Array(4)].flatMap((_,c)=>[...Array(4)].map((_,r)=>w[(i+2)*4+c][r])).slice(0,8))}…</span>`).join('<br>')}<br><span class="sep"></span><span class="lbl">Result: </span><span class="vout">${hA(cipher)}</span>`,
    mapPos:6});

  // Step 9 Output
  out.push({badge:'Ciphertext',bc:'st',sc:'sct',dc:'dnt',title:'Final Ciphertext',
    why:'After 14 rounds, the state matrix is read column by column to produce 16 bytes. The result looks like random noise. Only the exact 256-bit key can reverse this.',
    glbl:'Encrypted output — 16 bytes',before:cipher,after:cipher,
    et:'State matrix read column by column',
    fm:`${[0,1,2,3].map(c=>`<span class="lbl">Col ${c}: </span><span class="vout">${[0,1,2,3].map(r=>H(ts(cipher)[r][c])).join(' ')}</span>`).join('<br>')}<br><span class="sep"></span><span class="lbl">Ciphertext: </span><span class="vout" style="font-size:.9rem;font-weight:700">${hA(cipher)}</span>`,
    mapPos:7});

  return out;
}