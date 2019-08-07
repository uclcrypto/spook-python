#! /usr/bin/python3

import spook

def test_spook_lwc(ad, m, k, n, c):
    p = k[16:]
    k = k[:16]
    print('AD', ad)
    print('M', m)
    print('k', k)
    print('p', p)
    print('n', n)
    print('c', c)
    c2 = spook.spook_encrypt(ad, m, k, p, n)
    m2 = spook.spook_decrypt(ad, c2, k, p, n)
    assert m2 == m, 'wrong inverse {} {}'.format(m, m2)
    assert c2 == c, 'not matching TV {} {}'.format(c, c2)

def fh(x):
    return bytes.fromhex(x)

def dec_tv_file(s):
    return [
            (d['AD'], d['PT'], d['Key'], d['Nonce'], d['CT'])
            for d in (dict((k, fh(v))
                for k, _, v in (y.split(' ') for y in x.split('\n')) if k != 'Count')
                for x in s.strip().split('\n\n'))
            ]

def test_tv_file(fname):
    tvs = dec_tv_file(open(fname).read())
    for i, tv in enumerate(tvs):
        print('TV', i)
        test_spook_lwc(*tv)

if __name__ == '__main__':
    spook.SMALL_PERM=False
    test_tv_file('tv_spook128su512.txt')
    test_tv_file('tv_spook128mu512.txt')
    spook.SMALL_PERM=True
    test_tv_file('tv_spook128su384.txt')
    test_tv_file('tv_spook128mu384.txt')

