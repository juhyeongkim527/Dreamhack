import string

target = [0x24, 0x27, 0x13, 0xC6, 0xC6, 0x13, 0x16, 0xE6, 0x47, 0xF5, 0x26, 0x96, 0x47,
          0xF5, 0x46, 0x27, 0x13, 0x26, 0x26, 0xC6, 0x56, 0x0F5, 0xC3, 0xC3, 0xF5, 0xE3, 0xE3, 0]

flag = ''
for target_val in target:
    for ch in string.printable:
        byte_ch = ch.encode()
        byte_val = int.from_bytes(byte_ch, 'little')
        if (16 * byte_val | byte_val >> 4) & 0xff == target_val:
            flag += ch

print('flag : DH{' + flag + '}')