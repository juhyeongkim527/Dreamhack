target_list = [
    0xAD, 0xD8, 0xCB, 0xCB, 0x9D, 0x97, 0xCB, 0xC4, 0x92, 0xA1, 0xD2,
    0xD7, 0xD2, 0xD6, 0xA8, 0xA5, 0xDC, 0xC7, 0xAD, 0xA3, 0xA1, 0x98, 0x4C, 0x00]

target_mod_list = []

for target in target_list:
    if target % 2 != 0:
        target_mod_list.append([target // 2, target//2 + 1])
    else:
        target_mod_list.append([target // 2, target//2])

i = 0
for target_mod in target_mod_list:
    print(f'target[{i}] : {target_list[i]}')
    print(target_mod[0])
    print(target_mod[1])
    print()
    i += 1
