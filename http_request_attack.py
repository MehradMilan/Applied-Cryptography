#توضیحات راه حل شکستن رمز:
# برای به‌دست آوردن طول کلید، ابتدا نیاز داشتیم مقداری از پیام رکوئست و ریسپانس را حدس بزنیم
# c = m ^ k
#             => c ^ c' = m ^ m'    
# c' = m' ^ k
#طبق این روش ابتدا رکوئست و ریسپانس رمز شده را اکس-اور کرده و بیت به بیت حدس‌مان از پیام آنها را اکس-اور کرده و متناظرا مقایسه می‌کنیم.
#این حدس ها بر قالب صورت کلی سرآیندهای پروتکل اچ‌تی‌تی‌پی انجام شد.
# در نهایت با مشاهده بایت‌های تکراری در کلید به‌دست آمده، طول کلید را ۶۸ بدست آورده و رمز بعد از این به سادگی می‌شکند.

import binascii
from operator import xor

request = '3cc6ed9d907b0dfdaa829948a6901986e9b454a875951dd21a9958a8625c53cfe197dafa94c1be76a14d02fe1934c1cf157a5d10e1315ee8db77bba806b8d15c90838c774cba86c4ba596be7be8e8509ae9318dea4aa15f1368662be78ef07f83f1e29aadb9c94cff1a6b26eeb613afe182ed08e027a'
response = '24ddea999f654fa3edd8c754efad1886b1d550a860c7588c0da619ed29032ae8e599c7e9db80ba64b51e0cfe6657f48404336b72841958e3953298b34490d857a492973e05e6d0f4ca2255e0f48dcf08ad8a4491f4ad14f162dd3ab72ba246fb7d0565e5d999dde693cee621fc5b09ea1938aaeb7d14'
req_res_xor = 0

def hex_to_bytes(h): #Converts the ciphers string to byte-array with hex indices.
    b = binascii.unhexlify(h)
    return b

def xor_byte_arrays(byte_req, byte_res): #Recieves two byte-arrays and xor their indices. returns in hex
    cipher_xor = [0] * len(byte_req)
    for i in range(len(byte_req)):
        cipher_xor[i] = hex(xor(byte_req[i],byte_res[i]))
    return cipher_xor

def xor_string_to_hex(str1, str2): #xor two strings. return the hex
    res = [hex((ord(a) ^ ord(b))) for a,b in zip(str1, str2)]
    return res

def string_to_hex(str): #Converts string to hex
    res = [hex(ord(a)) for a in str]
    return res

def check_index_message_is_cipher(req_str, res_str, start_index, end_index): #Checks if cipher-request ^ cipher_response = message_request ^ message_response
    xor_str = xor_string_to_hex(req_str, res_str)
    for i in range(start_index, end_index):
        if xor_str[i] != req_res_xor[i]:
            return False
    return True

def repeat_to_length(s, wanted): #extends the string (key) to cipher length
    return (s * (wanted//len(s) + 1))[:wanted]

def xor_string_and_hex(mess, h): #xor a char string and hex string. returns char string
    byte_message = string_to_hex(mess)
    byte_key = []
    for i in range(0, min(len(byte_message), len(h))):
        byte_key.append(xor(int(byte_message[i], base=16), h[i]))
    key_str = "".join(map(chr, byte_key))
    return key_str

def main():
    req = request
    res = response
    byte_req = hex_to_bytes(req)
    byte_res = hex_to_bytes(res)
    global req_res_xor
    req_res_xor = xor_byte_arrays(byte_req, byte_res) #cipher_req ^ cipher_res

    #Trying to guess ciphers
    guess_req_string = 'POST /login/index.php HTTP/1.1\r\nHost: cw.sharif.edu\r\nContent-Length: 38'
    guess_res_string = 'HTTP/1.1 303 See Other\r\nContent-Language: fa\r\nSet-Cookie: MoodleSession'
    start_index = 0
    end_index = min(len(guess_req_string), len(guess_res_string))
    check_index_message_is_cipher(guess_req_string, guess_res_string, start_index, end_index)

    #Finding out the key
    key_str = xor_string_and_hex(guess_req_string, byte_req)[:68]
    key_str = repeat_to_length(key_str, len(byte_req))

    #Calculating messages with known key
    message_request = xor_string_and_hex(key_str, byte_req)
    message_response = xor_string_and_hex(key_str, byte_res)

    
    print("Key:\n" + key_str + "\n")
    print("Request Message:\n" + "Request= " + message_request + "\n")
    print("Response Message:\n" + "Response= " + message_response + "\n")
    return

if __name__ == "__main__":
    main()
