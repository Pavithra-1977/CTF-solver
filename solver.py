import os,re,base64,binascii,hashlib,string,json,math,urllib.parse,html as _h
from datetime import datetime
try:
    from Crypto.PublicKey import RSA as _R
    from Crypto.Cipher import AES
    PYCRYPTO=True
except Exception: PYCRYPTO=False
try:
    from sympy import factorint; SYMPY=True
except Exception: SYMPY=False
try:
    import gmpy2; GMPY2=True
except Exception: GMPY2=False

def log_entry(l,c,m): return {"level":l,"category":c,"message":m,"ts":datetime.now().strftime("%H:%M:%S")}
def _mk(s,f=None,me=None,d=""): return {"success":s,"flag":f,"method":me,"details":d}
def _L(logs,l,c,m): logs.append(log_entry(l,c,m))

def find_flag(t,ff):
    if not t: return None
    if isinstance(t,(bytes,bytearray)): t=t.decode("utf-8","ignore")
    m=re.search(re.escape(ff)+r"[^}\n]{0,200}}",t,re.I)
    if m: return m.group(0)
    s=t.strip()
    if s.lower().startswith(ff.lower()): return s
    return None

def _pr(b,th=0.85):
    if not b: return False
    return sum(1 for x in b if 32<=x<127 or x in(9,10,13))/len(b)>=th

HASH={'MD5':32,'SHA1':40,'SHA224':56,'SHA256':64,'SHA384':96,'SHA512':128}
def detect_hash_type(t):
    t=t.strip(); r=[]
    for n,ln in HASH.items():
        if re.fullmatch(r'[0-9a-fA-F]{%d}'%ln,t): r.append(n)
    return r

def _crack(h,ht,wl,mx=2000000):
    if not os.path.isfile(wl): return None
    fn={'MD5':hashlib.md5,'SHA1':hashlib.sha1,'SHA224':hashlib.sha224,'SHA256':hashlib.sha256,'SHA384':hashlib.sha384,'SHA512':hashlib.sha512}.get(ht)
    if not fn: return None
    tgt=h.strip().lower()
    try:
        with open(wl,'rb') as f:
            for i,line in enumerate(f):
                if i>=mx: break
                w=line.rstrip(b'\r\n')
                if fn(w).hexdigest()==tgt: return w.decode('utf-8','replace')
    except Exception: pass
    return None

def solve_hash(ct,ff,wl,logs):
    _L(logs,"info","hash","=== Hash ID ===")
    t=ct.strip(); ts=detect_hash_type(t)
    if not ts: _L(logs,"info","hash","No hash detected."); return _mk(False)
    _L(logs,"info","hash","Detected: "+", ".join(ts))
    for ht in ts:
        _L(logs,"info","hash","Cracking %s ..."%ht)
        p=_crack(t,ht,wl)
        if p:
            _L(logs,"success","hash","Cracked -> "+p)
            fl=find_flag(p,ff)
            return _mk(True,fl or p,"Dictionary attack (%s)"%ht,p)
    _L(logs,"warning","hash","Not found in wordlist.")
    return _mk(False,details="Hash: "+", ".join(ts))

def _rot13(t): return t.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz","NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
def solve_encodings(ct,ff,logs):
    _L(logs,"info","encoding","=== Encodings ===")
    def tb64(t):
        try:
            d=base64.b64decode(t.strip()+"==")
            return d.decode("utf-8","ignore") if _pr(d) else None
        except Exception: return None
    def thex(t):
        t=t.strip().replace(" ","").replace("\n","")
        try:
            if len(t)%2==0:
                d=bytes.fromhex(t); return d.decode("utf-8","ignore") if _pr(d) else None
        except Exception: return None
    def tb32(t):
        try:
            d=base64.b32decode(t.strip().upper()); return d.decode("utf-8","ignore") if _pr(d) else None
        except Exception: return None
    def tb85(t):
        try:
            d=base64.b85decode(t.strip()); return d.decode("utf-8","ignore") if _pr(d) else None
        except Exception: return None
    def turl(t):
        d=urllib.parse.unquote(t); return d if d!=t else None
    def tbin(t):
        t=t.strip().replace(" ","")
        if re.fullmatch(r"[01]+",t) and len(t)%8==0:
            try: return "".join(chr(int(t[i:i+8],2)) for i in range(0,len(t),8))
            except Exception: return None
    fns=[("Base64",tb64),("Hex",thex),("Base32",tb32),("Base85",tb85),("URL",turl),("Binary",tbin),("ROT13",_rot13)]
    def rec(t,d,ch):
        if d>3: return None,None
        for n,fn in fns:
            try: r=fn(t)
            except Exception: r=None
            if not r: continue
            c=ch+" -> "+n if ch else n
            fl=find_flag(r,ff)
            if fl: return fl,c
            df,dc=rec(r,d+1,c)
            if df: return df,dc
        return None,None
    fl,ch=rec(ct,0,"")
    if fl: _L(logs,"success","encoding","FLAG via "+ch); return _mk(True,fl,ch,fl)
    _L(logs,"info","encoding","No encoding flag.")
    return _mk(False)

def _caesar(t,s): return "".join(chr((ord(c)-(65 if c.isupper() else 97)-s)%26+(65 if c.isupper() else 97)) if c.isalpha() else c for c in t)
def solve_caesar(ct,ff,logs):
    _L(logs,"info","classical","=== Caesar/ROT13 ===")
    for s in range(1,26):
        c=_caesar(ct,s); fl=find_flag(c,ff)
        if fl: _L(logs,"success","classical","FLAG shift=%d"%s); return _mk(True,fl,"Caesar shift=%d"%s if s!=13 else "ROT13",c)
    return _mk(False)

def _atbash(t): return "".join(chr((65 if c.isupper() else 97)+25-(ord(c)-(65 if c.isupper() else 97))) if c.isalpha() else c for c in t)
def solve_atbash(ct,ff,logs):
    _L(logs,"info","classical","=== Atbash ===")
    c=_atbash(ct); fl=find_flag(c,ff)
    if fl: _L(logs,"success","classical","FLAG Atbash"); return _mk(True,fl,"Atbash",c)
    return _mk(False)

def _vig(t,k):
    k=k.lower(); r=[]; i=0
    for c in t:
        if c.isalpha():
            s=ord(k[i%len(k)])-97; b=65 if c.isupper() else 97
            r.append(chr((ord(c)-b-s)%26+b)); i+=1
        else: r.append(c)
    return "".join(r)
def solve_vigenere(ct,ff,logs):
    _L(logs,"info","classical","=== Vigenere ===")
    for k in ["key","secret","password","crypto","flag","ctf","cipher","python","picoctf","lemon","hello","test","enigma"]:
        c=_vig(ct,k); fl=find_flag(c,ff)
        if fl: _L(logs,"success","classical","FLAG key=%s"%k); return _mk(True,fl,"Vigenere key='%s'"%k,c)
    return _mk(False)

def solve_xor(ct,ff,logs):
    _L(logs,"info","xor","=== XOR ===")
    raws=[]
    s=ct.strip().replace(" ","").replace("\n","")
    if re.fullmatch(r"[0-9a-fA-F]+",s) and len(s)%2==0:
        try: raws.append(bytes.fromhex(s))
        except Exception: pass
    try: raws.append(base64.b64decode(ct.strip()))
    except Exception: pass
    raws.append(ct.encode("utf-8","ignore"))
    for raw in raws:
        for k in range(256):
            t=bytes(b^k for b in raw).decode("utf-8","ignore")
            fl=find_flag(t,ff)
            if fl: _L(logs,"success","xor","FLAG XOR key=0x%02X"%k); return _mk(True,fl,"Single-byte XOR key=0x%02X"%k,t)
    return _mk(False)

def _egcd(a,b):
    if a==0: return b,0,1
    g,x,y=_egcd(b%a,a); return g,y-(b//a)*x,x
def _inv(a,m):
    g,x,_=_egcd(a,m); return x%m if g==1 else None
def _isqrt(n):
    if GMPY2: return int(gmpy2.isqrt(n))
    return math.isqrt(n)
def _fermat(n,mx=200000):
    if n%2==0: return 2,n//2
    a=_isqrt(n)+1; b2=a*a-n
    for _ in range(mx):
        b=_isqrt(b2)
        if b*b==b2: return a-b,a+b
        a+=1; b2=a*a-n
    return None
def _introot(n,k):
    if GMPY2:
        r,e=gmpy2.iroot(n,k); return int(r)
    u=n; s=n+1
    while u<s:
        s=u; t=(k-1)*s+n//s**(k-1); u=t//k
    return s
def _cfrac(e,n):
    a,b=e,n; n0,n1=0,1; d0,d1=1,0
    while b:
        q=a//b; a,b=b,a-q*b; n0,n1=n1,q*n1+n0; d0,d1=d1,q*d1+d0
        yield n0,d0
def _wiener(e,n):
    for k,d in _cfrac(e,n):
        if k==0 or d==0 or (e*d-1)%k: continue
        phi=(e*d-1)//k; b=n-phi+1; dis=b*b-4*n
        if dis<0: continue
        s=_isqrt(dis)
        if s*s!=dis: continue
        p=(b+s)//2; q=(b-s)//2
        if p*q==n: return d,p,q
    return None
def _dec(n,e,c,p,q,ff):
    phi=(p-1)*(q-1); d=_inv(e,phi)
    if d is None: return None
    m=pow(c,d,n); bl=(m.bit_length()+7)//8
    if bl==0: return None
    mb=m.to_bytes(bl,"big")
    if mb[:2]==b'\x00\x02':
        i=mb.find(b'\x00',2)
        if i!=-1: mb=mb[i+1:]
    pt=mb.decode("utf-8","ignore")
    return {"pt":pt,"flag":find_flag(pt,ff)}
def solve_rsa(rp,ff,logs):
    _L(logs,"info","rsa","=== RSA ===")
    n=rp.get("n"); e=rp.get("e"); c=rp.get("c")
    if not n: _L(logs,"info","rsa","No modulus."); return _mk(False)
    _L(logs,"info","rsa","N bits=%d e=%s"%(n.bit_length(),e))
    p=rp.get("p"); q=rp.get("q")
    if p and q and c:
        r=_dec(n,e,c,p,q,ff)
        if r and r["flag"]: _L(logs,"success","rsa","FLAG p,q given"); return _mk(True,r["flag"],"RSA (p,q known)",r["pt"])
    if c:
        _L(logs,"info","rsa","Fermat ...")
        f=_fermat(n)
        if f:
            r=_dec(n,e,c,f[0],f[1],ff)
            if r and r["flag"]: _L(logs,"success","rsa","FLAG Fermat"); return _mk(True,r["flag"],"RSA Fermat factorization",r["pt"])
        if e:
            _L(logs,"info","rsa","Wiener ...")
            w=_wiener(e,n)
            if w:
                r=_dec(n,e,c,w[1],w[2],ff)
                if r and r["flag"]: _L(logs,"success","rsa","FLAG Wiener"); return _mk(True,r["flag"],"RSA Wiener attack",r["pt"])
        if e==3:
            _L(logs,"info","rsa","Cube root ...")
            m=_introot(c,3)
            if m**3==c:
                pt=m.to_bytes((m.bit_length()+7)//8,"big").decode("utf-8","ignore")
                fl=find_flag(pt,ff)
                if fl: _L(logs,"success","rsa","FLAG cube root"); return _mk(True,fl,"RSA e=3 cube root",pt)
        if SYMPY and n.bit_length()<=256:
            _L(logs,"info","rsa","sympy factor ...")
            try:
                fa=list(factorint(n).keys())
                if len(fa)==2:
                    r=_dec(n,e,c,fa[0],fa[1],ff)
                    if r and r["flag"]: _L(logs,"success","rsa","FLAG sympy"); return _mk(True,r["flag"],"RSA sympy factorization",r["pt"])
            except Exception: pass
    _L(logs,"info","rsa","RSA exhausted.")
    return _mk(False)

def parse_files(fps,logs):
    _L(logs,"info","file","=== Files ===")
    m={}; txts=[]
    for fp in fps:
        ext=os.path.splitext(fp)[1].lower()
        try:
            if ext in(".pem",".key",".pub") and PYCRYPTO:
                k=_R.import_key(open(fp,"rb").read()); m["n"]=k.n; m["e"]=k.e
                if k.has_private(): m["p"]=k.p; m["q"]=k.q
            elif ext==".json":
                d=json.load(open(fp))
                for f in("n","e","d","p","q","c"):
                    if f in d: m[f]=int(d[f],16) if isinstance(d[f],str) and not d[f].isdigit() else int(d[f])
            else:
                ct=open(fp,"r",errors="ignore").read(); txts.append(ct)
                for v in("n","e","d","p","q","c"):
                    mm=re.search(r"(?:^|\n)\s*%s\s*=\s*(0x[0-9a-fA-F]+|\d{5,})"%v,ct,re.I|re.M)
                    if mm: m[v]=int(mm.group(1),16) if mm.group(1).startswith("0x") else int(mm.group(1))
        except Exception as ex: _L(logs,"warning","file","parse fail: %s"%ex)
    return {k:m[k] for k in("n","e","d","p","q","c") if k in m},txts

def run_all_solvers(ct,fps,ff,wl):
    logs=[]; att=[]; det=[]; res=None
    _L(logs,"info","init","CTF Crypto Solver")
    _L(logs,"info","init","flag='%s' len=%d files=%d"%(ff,len(ct),len(fps)))
    rp,txts=parse_files(fps,logs)
    texts=[ct]+[t for t in txts if t.strip()]
    def run(nm,fn,*a):
        nonlocal res; att.append(nm)
        try:
            r=fn(*a)
            if r.get("success"): res=r
            return r
        except Exception as ex:
            import traceback; _L(logs,"error","solver","%s crashed: %s"%(nm,traceback.format_exc())); return _mk(False)
    for t in texts:
        for ln in t.splitlines():
            if detect_hash_type(ln.strip()):
                run("hash",solve_hash,ln.strip(),ff,wl,logs)
                if res: break
        if res: break
    if res: return _final(res,logs,att,det)
    for t in texts:
        run("enc",solve_encodings,t,ff,logs)
        if res: break
    if res: return _final(res,logs,att,det)
    for t in texts:
        run("xor",solve_xor,t,ff,logs)
        if res: break
    if res: return _final(res,logs,att,det)
    for t in texts:
        for fn in [solve_caesar,solve_atbash,solve_vigenere]:
            run(fn.__name__,fn,t,ff,logs)
            if res: break
        if res: break
    if res: return _final(res,logs,att,det)
    if not rp.get("c") and ct.strip().isdigit(): rp["c"]=int(ct.strip())
    if rp: run("rsa",solve_rsa,rp,ff,logs)
    if res: return _final(res,logs,att,det)
    _L(logs,"warning","final","No flag found.")
    return _final(None,logs,att,det)

def _final(res,logs,att,det):
    if res and res.get("success"):
        return {"flag_found":True,"flag":res["flag"],"method":res["method"],"details":res.get("details",""),"logs":logs,"analysis":{"detected_types":list(set(det)),"attempted_methods":att}}
    return {"flag_found":False,"flag":None,"method":None,"details":"","logs":logs,"analysis":{"detected_types":list(set(det)),"attempted_methods":att}}
