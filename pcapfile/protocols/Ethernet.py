# vim: expandtab tabstop=4 fileencoding=utf-8
#
# Copyright © 2011 Fábio Olivé Leite <fleite@redhat.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from struct import Struct
from IP import IP

def macstr(mac):
    return ":".join(map(lambda x: "{0:02x}".format(x), mac))

class Ethernet():
    struct = Struct("!6B6BH")
    size = struct.size

    IP = 0x0800
    ARP = 0x0806

    def __init__(self, packet):
        p = packet.nextHeader
        unpacked = Ethernet.struct.unpack(packet.rawData[p:p+Ethernet.size])
        self.dst = unpacked[0:6]
        self.dstStr = macstr(self.dst)
        self.src = unpacked[6:12]
        self.srcStr = macstr(self.src)
        self.proto = unpacked[12]
        packet.nextHeader += Ethernet.size
        if self.proto == Ethernet.IP:
            packet.protocols.append("IP")
            packet.ip = IP(packet)

    def __repr__(self):
        return "Ethernet(dst={0}, src={1}, proto={2:04x})".format(
            self.dstStr, self.srcStr, self.proto)

