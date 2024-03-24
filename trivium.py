from collections import deque
from bitstring import BitArray

class Trivium:
    def __init__(self, key, iv):
        self.key = key
        self.IV = iv

        # init state
        # register A
        li = iv
        li += [0] * 13
        # register B
        li += key
        li += [0, 0, 0, 0]
        # register C
        li += [0] * 108
        li += [1, 1, 1]
        self.state = deque(li)

        for i in range(1152):
            self.gen_key_stream()

    def gen_key_stream(self):
        t1 = self.state[65] ^ (self.state[90] & self.state[91]) ^ self.state[92]
        t2 = self.state[161] ^ (self.state[174] & self.state[175]) ^ self.state[176]
        t3 = self.state[242] ^ (self.state[285] & self.state[286]) ^ self.state[287]
        s = t1 ^ t2 ^ t3

        new_0 = self.state[68] ^ t3
        new_93 = self.state[170] ^ t1
        new_177 = self.state[263] ^ t2

        self.state.rotate()
        self.state[0] = new_0
        self.state[93] = new_93
        self.state[177] = new_177

        return s

    def key_stream(self, length):
        li = []
        for i in range(length):
            li.append(self.gen_key_stream())
        return li

def encrypt_file(input_file, output_file, key, iv):
    trivium = Trivium(key, iv)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        keystream = trivium.key_stream(1000000)
        for byte in f_in.read():
            encrypted_byte = byte ^ keystream.pop(0)
            f_out.write(bytes([encrypted_byte]))

def main():
    input_file = "data_trivium/alice29.txt"
    output_file = "encrypted_trivium/alice29_encrypted"
    key = BitArray("0x0123456789abcdef01234")
    iv = BitArray("0x0123456789abcdef01234")
    encrypt_file(input_file, output_file, key, iv)


main()