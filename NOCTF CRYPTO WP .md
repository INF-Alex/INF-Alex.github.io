# NOCTF CRYPTO WP

## miaES

根据代码发现加密方式类似AES加密，明文通过函数`encrypt_flag`得出：

```python
def encrypt_flag(iv, plaintext):
    s = iv
    ciphertext = b''
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([0]) * (pad_len - 1) + bytes([pad_len])
    for i in range(0, len(plaintext), 16):
        stream = encrypt(key, s)
        xor = lambda x, y: bytes([a ^ b for a, b in zip(x, y)])
        ciphertext += xor(plaintext[i:i + 16], stream)
        s = stream
    return ciphertext
```

观察到明文由`ciphertext += xor(plaintext[i:i + 16], stream)`产生，即`ciphertext[i:i+16] == xor(plaintext[i:i + 16], stream)`。

根据异或操作的特征，得到`plaintext[i:i+16] == xor(ciphertext[i:i + 16], stream)`。

由于key和iv已知，且stream通过key和iv得到，因此定义decrypt函数：

```python
def decrypt_flag(iv, ciphertext):
    s = iv
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        stream = encrypt(key, s)
        xor = lambda x, y: bytes([a ^ b for a, b in zip(x, y)])
        plaintext += xor(ciphertext[i:i + 16], stream)
        s = stream
    return plaintext
```

由于encrypt_flag时将FLAG扩展，因此decrypt_flag得到的明文需要截去扩展的字节，得到FLAG的代码如下：

```python
plaintext = decrypt_flag(iv, ciphertext)
print(plaintext)
ans = str(plaintext)
print(ans[2:ans.index('}')+1])
```

运行结果如图：

![image-20231030134047375](C:\Users\86180\AppData\Roaming\Typora\typora-user-images\image-20231030134047375.png)

## imitate

发现`jwt.encode`为base64编码+RSA加密。根据题目进行base64解码，转化为RSA的形式：

```python
def b64urlDecode(data):
    data = data.replace(b'-', b'+').replace(b'_', b'/')
    while len(data) % 4 != 0:
        data += b'='
    return b64decode(data)

Ca = Ca.split(b'.')
Cb = Cb.split(b'.')
c1, m1 = Ca[1], Ca[2]
c2, m2 = Cb[1], Cb[2]
c1 = bytes_to_long(b64urlDecode(c1))
c2 = bytes_to_long(b64urlDecode(c2))
m1 = int(b64urlDecode(m1), 16)
m2 = int(b64urlDecode(m2), 16)
```

由此可得，`c1 = pow(m1, e, n), c2 = pow(m2, e, n)`（其中只有n未知），

即`m1 ** e == c1 + k1 * n, m2 ** e == c2 + k2 * n`，

所以`m1 ** e - c1 == k1 * n, m2 ** e - c2 == k2 * n`。

因此`gcd(k1 * n, k2 * n) == gcd(m1 ** e - c1, m2 ** e - c2)`,

即`n = gcd(m1 ** e - c1, m2 ** e - c2)`。

```python
m1 = gmpy2.mpz(m1)
m2 = gmpy2.mpz(m2)
n = gmpy2.gcd(m1**e-c1,m2**e-c2)
```

由于`gift = (d * n * e) % Mod`中只有`d`未知，且`d < Mod` 因此可求解`d`：

```python
_e = inverse(e, Mod)
_n = inverse(n, Mod)
d = _n * _e * gift % Mod
```

已知`e`、`d`，即可知`k * (p-1) * (q-1) == e * d - 1`，又`p * q == n`，所以：`p + q == (n - (e*d-1) // k + 1)`，其中`k`为`1~e-1`的可以整除`(e*d-1)`的正整数，原本试图通过韦达定理构造一元二次方程求解，但是碰到了问题：

```python
for k in range(1,e):
    if (e*d-1) % k == 0:
        phi = (e*d-1)//k
        a = 1
        b = -(n - phi + 1)
        c = n
        p = (-b + gmpy2.sqrt(b * b - 4 * a * c))//(2*a)
        q = (-b - gmpy2.sqrt(b * b - 4 * a * c))//(2*a)
        if p*q==n:
            print(p,q)
```

于是上网搜索资料，通过以下代码解出`p`,`q`：

```python
def getpq(n,e,d):
    while True:
        k = e * d - 1
        g = random.randint(0, n)
        while k%2==0:
            k=k//2
            temp=gmpy2.powmod(g,k,n)-1
            if gmpy2.gcd(temp,n)>1 and temp!=0:
                return gmpy2.gcd(temp,n)
p = getpq(n, e, d)
q = n // p            
```

最后，由`C = (p * bytes_to_long(flag)) % Mod`解出FLAG:

```python
i = 0
while True:
    if (C + i * Mod) % p == 0:
        print(long_to_bytes((C + i * Mod) // p))
    if (C + i * Mod) % q == 0:
        print(long_to_bytes((C + i * Mod) // q))
    i += 1
```

完整代码如下：

```python
from base64 import b64decode
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
import gmpy2
import random

gift = 62385476978700501214089568185195649659274934363059744211931165834781435414849228446978742796363227760030554566402307253032004623212196365620974775430516021958860747745193274456246017264262999271411031601011550197243951058824991129679927663692540286012424727260428137908706271075996269463132650147692707777400
Mod = 139783530492499989366806186190970201707045784617955510994670668264365125613780534146207604662234972781205415792315794694804125806787962550504358642185835486015743979918457538944006966377376366330483194448343751231567467051085883090503081476738133080325775972135216360160821424559840800702984626714613403410341
Ca = b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.TWF5YjM.NGI5N2IwYjUyY2Y0ZTlkMTJlZTFkNjhkYTE5MTRlZTUwY2UxOGRjMWViNGZkZDE5YWZiNDIzMGY3OWE2ZmI5YzQwNTI3ZGM1OGQ0OTIxZmI5ZWI3Zjc1ZGY2ZjBhZGI2MWU1YWQ1MWM4MjA4M2Y5M2IzZWZlZDVjZTM2YWRjNDQ'
Cb = b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.Q3J5cDc.MWJjNTI4NDIzNGU2MjgxZmY4ZDY4YmUwZTNmMWM3ZmQ0OTNmNDAwMDMzNTkyMjRmNjcwOWVmZTM0MjM2OGM0ZDc5ZDBmNTYwYzAzZGQ4ZDU4ZDRhNjk2NzU1MDU3NjVlZDBjNTgwOWJkMjViZWZlNTlmODY3NTZkYzI0NmJmZg'
C = 3454932108453579916131399430502511588230619545318881430991349901038902611605453734080149058230878714433909067049429244397457303301903246046075369382663670798080063018482644701084995319681682533608988693424511755031

def b64urlDecode(data):
    data = data.replace(b'-', b'+').replace(b'_', b'/')
    while len(data) % 4 != 0:
        data += b'='
    return b64decode(data)

Ca = Ca.split(b'.')
Cb = Cb.split(b'.')
c1, m1 = Ca[1], Ca[2]
c2, m2 = Cb[1], Cb[2]
c1 = bytes_to_long(b64urlDecode(c1))
c2 = bytes_to_long(b64urlDecode(c2))
m1 = int(b64urlDecode(m1), 16)
m2 = int(b64urlDecode(m2), 16)

e = 0x10001
m1 = gmpy2.mpz(m1)
m2 = gmpy2.mpz(m2)
n = gmpy2.gcd(m1**e-c1,m2**e-c2)

_e = inverse(e, Mod)
_n = inverse(n, Mod)
d = _n * _e * gift % Mod

assert pow(c1,d,n) == m1
assert pow(c2,d,n) == m2
assert pow(m1,e,n) == c1
assert pow(m2,e,n) == c2

def getpq(n,e,d):
    while True:
        k = e * d - 1
        g = random.randint(0, n)
        while k%2==0:
            k=k//2
            temp=gmpy2.powmod(g,k,n)-1
            if gmpy2.gcd(temp,n)>1 and temp!=0:
                return gmpy2.gcd(temp,n)
            
p = getpq(n, e, d)
q = n // p

assert p * q == n

i = 0
while True:
    if (C + i * Mod) % p == 0:
        print(long_to_bytes((C + i * Mod) // p))
        break
    if (C + i * Mod) % q == 0:
        print(long_to_bytes((C + i * Mod) // q))
        break
    i += 1
```

运行结果如图：

![image-20231030142302063](C:\Users\86180\AppData\Roaming\Typora\typora-user-images\image-20231030142302063.png)

