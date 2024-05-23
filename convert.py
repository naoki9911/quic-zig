import sys

recv_msg = bytes.fromhex(sys.argv[1])

print("= [_]u8{")
i = 0
for b in recv_msg:
    print("0x{:02X}, ".format(b), end='')
    i += 1
    if i % 10 == 0:
        print("")
print("};")
