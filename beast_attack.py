import requests, time
import binascii
from math import ceil

class Client:
    def __init__(self, url, username):
        self.session = requests.Session()  # use same session throughout lifetime
        self.username = username
        self.url = url

    def login(self, password):
        retry = 0
        while retry < 3:
            response = self.session.get(
                f"{self.url}?user={self.username}&pass={password}"
            )
            if response.ok:
                return response.text
            retry += 1
            time.sleep(1)
        print("error sending request. retry exceeded.")
        exit(-1)

def bytes_to_int(b):
    i = int.from_bytes(b, "big")
    return i

def bytes_to_hex(b):
    h = binascii.hexlify(b).decode()
    return h

def int_to_bytes(i, length=None):
    if length is None:
        length = max(1, ceil(i.bit_length() / 8))
    b = i.to_bytes(length, "big")
    return b

def hex_to_bytes(h):
    b = binascii.unhexlify(h)
    return b

def xor_bytes(b1, b2, cycle=True):
    if len(b1) > len(b2):
        b1, b2 = b2, b1
    if cycle:
        b1 = (b1 * ceil(len(b2) / len(b1)))[: len(b2)]
    else:
        b2 = b2[: len(b1)]
    result = int_to_bytes(bytes_to_int(b1) ^ bytes_to_int(b2), length=len(b1))
    return result

def xor_hex(h1, h2):
    return bytes_to_hex(xor_bytes(hex_to_bytes(h1), hex_to_bytes(h2)))

if __name__ == "__main__":
    STD_NUM = "99105775"
    client = Client("https://oracle.darkube.app", STD_NUM)
    password = ''
    p = ''

    for j in range(15):
        ms = (b'0'*15).hex()
        cs = client.login(ms)
        ivs = cs[-32:]

        m0 = (b'A'*(15-j)).hex()
        c0 = client.login(m0)
        c0b0 = c0[:32]
        iv = cs[-32:]
        p = ''

        m = (b'A'*(15-j)).hex()
        m = m + password

        for i in range(256):
            mi = m + int_to_bytes(i).hex()
            message = xor_bytes(hex_to_bytes(mi), hex_to_bytes(ivs))
            message = bytes_to_hex(xor_bytes(message, hex_to_bytes(iv)))
            c = client.login(message)
            ci = c[:32]
            iv = c[-32:]
            if (ci == c0b0):
                p = mi[(30):(32)]
                print(p)
                password = password + p
                break
        res = client.login(password)
        if (res.startswith('logged in.')):
            break

def hex_to_string(h):
    return ''.join([chr(int(''.join(c), 16)) for c in zip(h[0::2],h[1::2])])
print('Password in HEX:     ' + password)
print('Password in STRING:     ' + hex_to_string(password))
print(client.login(password))