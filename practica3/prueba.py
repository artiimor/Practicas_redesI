import struct

header = bytearray(4)
datagram = bytearray()
header[0] = (4 << 4)+(20//4)
datagram += (header)
datagram += (header)
print(datagram)
