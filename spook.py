# MIT License
#
# Copyright (c) 2019, 2020 Gaëtan Cassiers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Spook cipher.

CAUTION: This implementation is intended for cipher analysis purpose only and
NOT FITTED for use with real-life data: it is sensitive to timing side-channel
attacks and is extremely inefficient.

Usage:
    The spook_encrypt and spook_decrypt functions take as input bytes objects.
    The variant is selected according to the global constant SMALL_PERM and to
    the length of the input k (16 bytes for 'su' and 32 bytes for 'mu').

Implementation details:
    The LS state matrix is mainly represented as a list of 4 integers, each one
    representing a row (little-endian).  A m-LS state is implemented as a list
    of LS states.
"""

__version__= '2.0'

SMALL_PERM=False
N_STEPS=6

LS_SIZE = 16 # bytes
BLOCK_SIZE =lambda: LS_SIZE if SMALL_PERM else 2*LS_SIZE

RC = [
        (1, 0, 0, 0),
        (0, 1, 0, 0),
        (0, 0, 1, 0),
        (0, 0, 0, 1),
        (1, 1, 0, 0),
        (0, 1, 1, 0),
        (0, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 0, 1, 0),
        (0, 1, 0, 1),
        (1, 1, 1, 0),
        (0, 1, 1, 1),
        ]

def rotr(x, c):
    return (x >> c) | ((x << (32-c)) & 0xFFFFFFFF)

def lbox(x, y):
    a = x ^ rotr(x, 12)
    b = y ^ rotr(y, 12)
    a = a ^ rotr(a, 3)
    b = b ^ rotr(b, 3)
    a = a ^ rotr(x, 17)
    b = b ^ rotr(y, 17)
    c = a ^ rotr(a, 31)
    d = b ^ rotr(b, 31)
    a = a ^ rotr(d, 26)
    b = b ^ rotr(c, 25)
    a = a ^ rotr(c, 15)
    b = b ^ rotr(d, 15)
    return (a, b)

def lbox_inv(x, y):
    a = x ^ rotr(x, 25)
    b = y ^ rotr(y, 25)
    c = x ^ rotr(a, 31)
    d = y ^ rotr(b, 31)
    c = c ^ rotr(a, 20)
    d = d ^ rotr(b, 20)
    a = c ^ rotr(c, 31)
    b = d ^ rotr(d, 31)
    c = c ^ rotr(b, 26)
    d = d ^ rotr(a, 25)
    a = a ^ rotr(c, 17)
    b = b ^ rotr(d, 17)
    a = rotr(a, 16)
    b = rotr(b, 16)
    return (a, b)

def lbox_layer(x):
    return (*lbox(x[0], x[1]), *lbox(x[2], x[3]))

def lbox_layer_inv(x):
    return (*lbox_inv(x[0], x[1]), *lbox_inv(x[2], x[3]))

def sbox_layer(x):
    y1 = (x[0] & x[1]) ^ x[2]
    y0 = (x[3] & x[0]) ^ x[1]
    y3 = (y1 & x[3]) ^ x[0]
    y2 = (y0 & y1) ^ x[3]
    return [y0, y1, y2, y3]

def sbox_layer_inv(x):
    y3 = (x[0] & x[1]) ^ x[2]
    y0 = (x[1] & y3) ^ x[3]
    y1 = (y3 & y0) ^ x[0]
    y2 = (y0 & y1) ^ x[1]
    return [y0, y1, y2, y3]

def add_rc(x, r, s=0):
    return list(row ^ (RC[r][i] << s) for i, row in enumerate(x))

def xor_states(x, y):
    return list(xr ^ yr for xr, yr in zip(x, y))

def tweakey(key, tweak):
    tx = (tweak[0]^tweak[2], tweak[1]^tweak[3])
    tk = [tweak, (*tx , tweak[0], tweak[1]), (tweak[2], tweak[3], *tx)]
    return [list(k^t for k, t in zip(key, tk_r)) for tk_r in tk]

def dbox(x):
    if SMALL_PERM:
        y = [[0, 0, 0, 0] for _ in range(3)]
        for i in range(4):
            y[0][i] = x[0][i]^x[1][i]^x[2][i]
            y[1][i] = x[0][i]^x[2][i]
            y[2][i] = x[0][i]^x[1][i]
    else:
        y = [[0, 0, 0, 0] for _ in range(4)]
        for i in range(4):
            y[0][i] = x[1][i]^x[2][i]^x[3][i]
            y[1][i] = x[0][i]^x[2][i]^x[3][i]
            y[2][i] = x[0][i]^x[1][i]^x[3][i]
            y[3][i] = x[0][i]^x[1][i]^x[2][i]
    return y

def clyde_encrypt(m, t, k):
    tk = tweakey(k, t)
    x = xor_states(m, tk[0])
    for s in range(N_STEPS):
        for rho in range(2):
            r = 2*s+rho
            x = sbox_layer(x)
            x = lbox_layer(x)
            x = add_rc(x, r)
        x = xor_states(x, tk[(s+1)%3])
    return x

def clyde_decrypt(c, t, k):
    tk = tweakey(k, t)
    x = c
    for s in reversed(range(N_STEPS)):
        x = xor_states(x, tk[(s+1)%3])
        for rho in reversed(range(2)):
            r = 2*s+rho
            x = add_rc(x, r)
            x = lbox_layer_inv(x)
            x = sbox_layer_inv(x)
    x = xor_states(x, tk[0])
    return x

def bytes2state(x):
    return list(x[4*i] | x[4*i+1] << 8 | x[4*i+2] << 16 | x[4*i+3] << 24 for i in range(4))

def state2bytes(x):
    return bytes((r >> 8*i) & 0xFF for r in x for i in range(4))

def app4(f, x):
    return list(f(xi) for xi in x)

def shadow(x):
    for s in range(N_STEPS):
        x = app4(sbox_layer, x)
        x = app4(lbox_layer, x)
        x = list(add_rc(xi, 2*s, i) for i, xi in enumerate(x))
        x = app4(sbox_layer, x)
        x = dbox(x)
        x = list(add_rc(xi, 2*s+1, i) for i, xi in enumerate(x))
    return x

def pad_bytes(b,n=LS_SIZE):
    return b.ljust(n, bytes((0,)))

def init_sponge_state(k, n):
    if len(k) == 32:
        # mu variant
        p = bytearray(k[16:])
        p[-1] &= 0x7F
        p[-1] |= 0x40
        p = bytes2state(p)
    else:
        assert len(k) == 16
        p = (0, 0, 0, 0)
    n = bytes2state(n)
    b = clyde_encrypt(n, p, bytes2state(k))
    if SMALL_PERM:
        x = [p, n, b]
    else:
        x = [p, n, (0, 0, 0, 0), b]
    return shadow(x)

def compress_block(x, block, mode, nbytes,pad):
    xb = state2bytes(x[0])
    if not SMALL_PERM:
        xb = xb + state2bytes(x[1])
    res = bytes(a ^ b for a, b in zip(xb, block))
    if mode == 'ENC':
        x_bytes = res
    elif mode == 'DEC':
        x_bytes = bytearray(xb)
        for i, b in enumerate(block[:nbytes]):
            x_bytes[i] = b
        if pad:
            x_bytes[nbytes] ^= 0x01
        x_bytes = bytes(x_bytes)
    x[0] = bytes2state(x_bytes[:LS_SIZE])
    if not SMALL_PERM:
        x[1] = bytes2state(x_bytes[LS_SIZE:])
    return x, res[:nbytes]

def compress_data(x, data, mode='ENC'):
    res = b''
    while len(data) >= BLOCK_SIZE():
        x, r = compress_block(x, data[:BLOCK_SIZE()], mode, BLOCK_SIZE(), False)
        res = res+r
        data = data[BLOCK_SIZE():]
        x = shadow(x)
    if data:
        pb = pad_bytes(data + b'\x01', n=BLOCK_SIZE())
        x, r = compress_block(x, pb, mode, len(data), True)
        res = res+r
        x[-2][0] ^= 0x2
        x = shadow(x)
    return x, res

def spook_encrypt(ad, m, k, n):
    x = init_sponge_state(k, n)
    x, _ = compress_data(x, ad)
    if m:
        x[-2][0] ^= 0x1
        x, c = compress_data(x, m)
    else:
        c = b''
    x[1][3] |= 0x80000000
    tag = state2bytes(clyde_encrypt(x[0], x[1], bytes2state(k)))
    return c+tag

def spook_decrypt(ad, c, k, n):
    x = init_sponge_state(k, n)
    x, _ = compress_data(x, ad)
    if len(c) > LS_SIZE:
        x[-2][0] ^= 0x1
        x, m = compress_data(x, c[:-LS_SIZE], mode='DEC')
    else:
        m = b''
    x[1][3] |= 0x80000000
    # NOTE: We do forward tag verification. In leveled implementations against
    # side-channel analysis, inverse tag verification should be performed to
    # enjoy the CIML2 property:
    # cst_time_cmp(x[0], clyde_decrypt(bytes2state(c[-LS_SIZE:], x[1], bytes2state(k))))
    tag = state2bytes(clyde_encrypt(x[0], x[1], bytes2state(k)))
    assert x[0] == clyde_decrypt(bytes2state(tag), x[1], bytes2state(k))
    if tag == c[-LS_SIZE:]:
        return m
    else:
        return None

