from Crypto.Util.number import bytes_to_long

FLAG = open("flag.txt", "rb").read()

step = len(FLAG) // 3
candies = [bytes_to_long(FLAG[i:i+step]) for i in range(0, len(FLAG), step)]

cnd1, cnd2, cnd3 = candies

with open('output.txt', 'w') as f:
    f.write(f'v1 = {cnd1**3 + cnd3**2 + cnd2}\n')
    f.write(f'v2 = {cnd2**3 + cnd1**2 + cnd3}\n')
    f.write(f'v3 = {cnd3**3 + cnd2**2 + cnd1}\n')
    f.write(f'v4 = {cnd1 + cnd2 + cnd3}\n')