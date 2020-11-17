#!/usr/bin/env python3

# sc25519.py

# access library for smartcards that support ed25519/x25519 operations
# according to the OpenPGP 3.4.1 spec, e.g. the Yubikey 5 series,
# and demo code

# Nov 2020 (c) <christian.tschudin@unibas.ch>
# MIT license

import nacl.bindings
from   smartcard.Exceptions import NoCardException
from   smartcard.System import readers
from   smartcard.util import toHexString, toBytes

# ----------------------------------------------------------------------
# x25519 and ed25519 support functions (for comparison of results)

def ed25519_import_seed(s):
    # input s: 32 random bytes
    return nacl.bindings.crypto_sign_seed_keypair(s)

def ed25519_sign(blob, seckey):
    return nacl.bindings.crypto_sign(blob, seckey)[:64]

def ed25519_verify_signature(pubkey, blob, signature):
    return nacl.bindings.crypto_sign_open(signature+blob, pubkey)

def ed25519_pk_to_curve(pub):
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(pub)

def ed25519_sk_to_curve(sec):
    return nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(sec)

def ed25519_diffie_hellman(sec, pub):
    scalar = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(sec)
    point =  nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(pub)
    return x25519_diffie_hellman(scalar, point)

def x25519_diffie_hellman(sec, pub):
    return nacl.bindings.crypto_scalarmult(sec, pub)

def x25519_decode_scalar(s):
    return bytes([s[0] & 248]) + s[1:-1] + bytes([(s[-1] | 64)&127])

# ----------------------------------------------------------------------

class SC25519: # currently for Yubikey 5

    DO_names = {
        b'\x81': 'in/out device flags',
        b'\x6e': 'Application Related Data',
        b'\x4f': 'Application identifier AID',
        b'\x5f\x52': 'Historical bytes',
        b'\x7f\x66': 'Extended length information', # two 32bit integers
        b'\x7f\x74': 'General feature management',
        b'\x73': 'Discretionary data objects',
        b'\xc0': 'Extended Capabilities Flag List',
        b'\xc1': 'Algorithm attributes - signature',
        b'\xc2': 'Algorithm attributes - decryption',
        b'\xc3': 'Algorithm attributes - authentication',
        b'\xc4': 'PW status Bytes',
        b'\xc5': 'Fingerprints',
        b'\xc6': 'List of CA-Fingerprints',
        b'\xcd': 'List of generation dates/times of key pairs',
        b'\xde': 'Key Information',
        b'\xd6': 'User Interaction Flag for PSO:CDS',
        b'\xd7': 'User Interaction Flag for PSO:DEC',
        b'\xd8': 'User Interaction Flag for PSO:AUT',
        b'\xd9': 'reserved'
    }
    composite_DOs = set([b'\x6e', b'\x7f\x74', b'\x73'])

    def __init__(self, rdr, pin1=None, pin3=None):
        self.conn = rdr.createConnection()
        self.conn.connect()
        self.atr = self.conn.getATR()
        self.pin1, self.pin3 = pin1, pin3
        # register OpenPGP app:
        apdu = toBytes('00 A4 04 00 06 D2 76 00 01 24 01 00')
        r = self.conn.transmit(apdu)
        if r[1:] != (0x90, 0):
            raise Exception('unable to find OpenPGP app')

    def __del__(self):
        try:
            self.conn.disconnect()
        except:
            pass

    @staticmethod
    def mktlv(tag, val):
        return tag + bytes([len(val)]) + val

    @staticmethod
    def _extract_tlv(buf):
        # return (tag, length, buffer minus the removed tag and len bytes)
        tag = buf[:1]
        if tag[0] & 0x1f == 0x1f: # ASN.1 tag encoding rule: two bytes
            tag = buf[:2]
        buf = buf[len(tag):]
        l = buf[0]
        if l == 0x81:
            l = buf[1]
            buf = buf[2:]
        elif l == 0x82:
            l = int.from_bytes(buf[1:3], 'big')
            buf = buf[3:]
        else:
            buf = buf[1:]
        return tag, l, buf
        
    @staticmethod
    def _extract_from_DO(path, buf):
        for t in path:
            # print(t.hex(), '-', buf.hex()) 
            if len(buf) == 0:
                return None
            while buf != b'':
                tag, l, buf = SC25519._extract_tlv(buf)
                if tag == t:
                    buf = buf[:l]
                    break
                buf = buf[l:]
        return None if len(buf) == 0 else buf

    @staticmethod
    def _parse_composite_DO(buf, lvl=0):
        if buf == b'': return None
        lst = {}
        while len(buf) > 0:
            tag, l, buf = SC25519._extract_tlv(buf)
            if not tag in SC25519.composite_DOs:
                lst[tag] = buf[:l]
            else:
                lst[tag] = SC25519._parse_composite_DO(buf[:l],lvl+1)
            buf = buf[l:]
        return lst

    @staticmethod
    def _pretty_print_tree(cdo, lvl=0):
        if type(cdo) == dict:
            for t,v in cdo.items():
                if t in SC25519.DO_names:
                    n = SC25519.DO_names[t]
                    print(f"{'    ' * lvl}{t.hex()} ={n}:")
                else:
                    print(f"{'    ' * lvl}{t.hex()}:")
                SC25519._pretty_print_tree(v, lvl+1)
        else:
            print(f"{'    ' * lvl}{cdo.hex()}")
        pass

    # ----------------------------------------------------------------------

    def verify(self, pid, pin):
        apdu = toBytes("00 20 00 8%d " % pid) + \
               [len(pin)] + list(pin) + [0]
        r = self.conn.transmit(apdu)
        # print('verify <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        return r[1:] == (0x90,0)

    def get_random_bytes(self, cnt):
        apdu = toBytes("00 84 00 00 ") + [cnt]
        r = self.conn.transmit(apdu)
        # print('random <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        if r[1:] != (0x90, 0): return None
        return bytes(r[0])

    def put_DO(self, tag, buf):
        if len(tag) == 1:
            tag = b'\x00' + tag
        apdu = list(self.mktlv(b'\x00\xda' + tag, buf))
        r = self.conn.transmit(apdu)
        # print('put_DO <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        return r[1:] == (0x90,0)

    def get_DO(self, tag):
        if len(tag) == 1:
            tag = b'\x00' + tag
        apdu = toBytes("00 CA ") + list(tag) + [0]
        r = self.conn.transmit(apdu)
        # print('get_data <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        if r[1] != 0x61 and r[1:] != (0x90,0):
            return None
        buf = r[0]
        while r[1] == 0x61:
            apdu = toBytes("00 C0 00 00 00")
            r = self.conn.transmit(apdu)
            if r[1:] != (0x90,0):
                return None
            # print('cont <', toHexString(r[0]), '>', toHexString(list(r[1:])))
            buf += r[0]
        return bytes(buf)

    def put_private_use(self, nr, buf):
        # before calling one has to verify() according to the slot number
        apdu = list(self.mktlv(b'\x00\xda\x01' + bytes([nr]), buf))
        r = self.conn.transmit(apdu)
        # print('put_priv_use <',toHexString(r[0]),'>',toHexString(list(r[1:])))
        return r[1:] == (0x90,0)

    def get_private_use(self, nr):
        # before calling one has to verify() according to the slot number
        apdu = toBytes("00 CA 01") + [nr] + [0]
        r = self.conn.transmit(apdu)
        # print('get_priv_use <',toHexString(r[0]),'>',toHexString(list(r[1:])))
        return bytes(r[0])
        
    def put_ed25519_signing_keys(self, pubk, seck):
        if self.pin3 != None:
            self.verify(3, self.pin3)
        a = self.mktlv(b'\x5f\x48', seck[:32] + pubk)
        b = self.mktlv(b'\x7f\x48', b'\x92\x20\x99\x20')
        c = self.mktlv(b'\x4d', b'\xb6\x00' + b + a)
        apdu = list(self.mktlv(b'\x00\xdb\x3f\xff', c))
        r = self.conn.transmit(apdu)
        # print('put_signk <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        if r[1:] != (0x90,0):
            return False
        self.get_DO(b'\xc1')
        # set the key type to ed25519:
        oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        return self.put_DO(b'\xc1', bytes([0x16] + oid))

    def put_x25519_dh_keys(self, pubk, seck):
        if self.pin3 != None:
            self.verify(3, self.pin3)
        # the YUBIKEY 5 wants the seck in big-endian format (!!):
        seck = bytes([seck[31-i] for i in range(32)])
        a = self.mktlv(b'\x5f\x48', seck + pubk)
        b = self.mktlv(b'\x7f\x48', b'\x92\x20\x99\x20')
        c = self.mktlv(b'\x4d', b'\xb8\x00' + b + a)
        apdu = list(self.mktlv(b'\x00\xdb\x3f\xff', c))
        r = self.conn.transmit(apdu)
        # print('put_dhk <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        if r[1:] != (0x90,0):
            return False
        # set the key type to x25519:
        oid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
        return self.put_DO(b'\xc2', bytes([0x12] + oid))

    def get_ed25519_signing_pubkey(self):
        apdu = toBytes("00 47 81 00 02 B6 00 00")
        r = self.conn.transmit(apdu)
        # print('get_pubkey <', toHexString(r[0]), '>',toHexString(list(r[1:])))
        if r[1:] != (0x90, 0): return None
        return self._extract_from_DO([b'\x7f\x49', b'\x86'], bytes(r[0]))

    def get_x25519_dh_pubkey(self):
        apdu = toBytes("00 47 81 00 02 B8 00 00")
        r = self.conn.transmit(apdu)
        # print('get_pubkey <', toHexString(r[0]), '>',toHexString(list(r[1:])))
        if r[1:] != (0x90, 0): return None
        return self._extract_from_DO([b'\x7f\x49', b'\x86'], bytes(r[0]))

    def ed25519_sign(self, msg):
        # use secret key on smartcard to sign
        if self.pin1 != None:
            self.verify(1, self.pin1)
        apdu = toBytes("00 2A 9E 9A") + [len(msg)] + list(msg) + [0]
        r = self.conn.transmit(apdu)
        # print('sign <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        if r[1:] != (0x90, 0): return None
        return bytes(r[0])

    def x25519_diffie_hellman(self, pubk):
        # use secret key on smartcard to derive shared secret
        if self.pin1 != None:
            self.verify(2, self.pin1)
        a = self.mktlv(b'\x86', pubk)
        b = self.mktlv(b'\x7f\x49', a)
        c = self.mktlv(b'\xa6', b)
        apdu = list(self.mktlv(b'\x00\x2a\x80\x86', c) + b'\x00')
        r = self.conn.transmit(apdu)
        # print('dh <', toHexString(r[0]), '>', toHexString(list(r[1:])))
        if r[1:] != (0x90,0):
            return None
        return bytes(r[0])

    pass

# ----------------------------------------------------------------------

if __name__ == '__main__':

    import sys
    import time

    print("Demo access to a YUBIKEY 5 hardware token\n")
    PW1 = b'123456'
    PW3 = b'12345678'

    for reader in readers():
        break # pick the first smartcard found
    else:
        print("no smartcard found")
        sys.exit(0)

    print("connecting to smartcard .", end='')
    for i in range(3):
        print('.', end='')
        try:
            hwtoken = SC25519(reader, PW1, PW3)
            print()
            break
        except Exception as e:
            if i < 2:
                time.sleep(1)
            else:
                raise e
    else:
        print("timeout")
        sys.exit(0)

    print("\na) get random bytes, generate ed25519 and derived x25519 keypairs")
    alice_seed = hwtoken.get_random_bytes(32)
    alice_pub, alice_sec = ed25519_import_seed(alice_seed)
    print("pubkey.ed", alice_pub.hex())
    print("seckey.ed", alice_sec.hex()[:64])
    print("         ", alice_sec.hex()[64:])
    print("pubkey.x ", ed25519_pk_to_curve(alice_pub).hex())
    print("seckey.x ", ed25519_sk_to_curve(alice_sec).hex())

    print("\nb) store ed25519 (signing) and derived x25519 (DH) keypairs")
    if not hwtoken.put_ed25519_signing_keys(alice_pub, alice_sec):
        print("  storing signing key failed!")
    elif not hwtoken.put_x25519_dh_keys(ed25519_pk_to_curve(alice_pub),
                                        ed25519_sk_to_curve(alice_sec)):
        print("  storing DH key failed!")
    else:
        print("ok")

    print("\nc) retrieve key attr:")
    hwtoken.verify(1, hwtoken.pin1)
    ard = hwtoken.get_DO(b'\x6e') # ARD, containing the key attributes
    if ard != None:
        buf = SC25519._extract_from_DO([b'\x6e', b'\x73'], ard)
        ddo = SC25519._parse_composite_DO(buf)  # discr. data objs
        print("c1=", ddo[b'\xc1'].hex())
        print("c2=", ddo[b'\xc2'].hex())
        # print("c3", ddo[b'\xc3'].hex())

    print("\nd) retrieve ed25519 and x25519 public keys:")
    print("ed25519.pubk=", hwtoken.get_ed25519_signing_pubkey().hex())
    print("x25519.pubk= ", hwtoken.get_x25519_dh_pubkey().hex())

    print("\ne) signing with ed25519 and comparison:")
    msg = hwtoken.get_random_bytes(80)
    sig1 = hwtoken.ed25519_sign(msg)
    sig2 = ed25519_sign(msg, alice_sec)
    ed25519_verify_signature(alice_pub, msg, sig2)
    print("sig.hwtoken= ", sig1.hex()[:64])
    print("             ", sig1.hex()[64:])
    print("sig.software=", sig2.hex()[:64])
    print("             ", sig2.hex()[64:])
    print("* match!" if sig1 == sig2 else "* mismatch :-(")

    print("\nf) Diffie-Hellman with x25519 and comparison:")
    s = hwtoken.get_random_bytes(32)
    bob_pub, bob_sec = ed25519_import_seed(s)
    shared_secret1 = hwtoken.x25519_diffie_hellman(ed25519_pk_to_curve(bob_pub))
    shared_secret2 = ed25519_diffie_hellman(alice_sec, bob_pub)
    print("dh.hwtoken=  ", shared_secret1.hex())
    print("dh.software= ", shared_secret2.hex())
    print("* match!" if shared_secret1 == shared_secret2 else "* mismatch :-(")
    
    print("\ng) retrieve application related data (ARD):")
    ard = hwtoken.get_DO(b'\x6e')
    tree_ard = SC25519._parse_composite_DO(ard)
    SC25519._pretty_print_tree(tree_ard, 1)

    print("\nh) put and get 'private use data' #2")
    hwtoken.verify(3, hwtoken.pin3)
    if not hwtoken.put_private_use(2, time.ctime().encode('utf8')):
        print("  put failed!")
    print("retrieved (should be now):",
          f"'{hwtoken.get_private_use(2).decode('utf8')}'")

    print("\nend-of-demo")

# eof
