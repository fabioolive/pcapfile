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
from helpers import macHex
from IP import IP
from ARP import ARP

class Ethernet():
    struct = Struct("!6s6sH")
    size = struct.size

    IP = 0x0800
    ARP = 0x0806

    def __init__(self, packet):
        p = packet.nextHeader
        unpacked = Ethernet.struct.unpack(packet.rawData[p:p+Ethernet.size])
        self.dst = unpacked[0]
        self.src = unpacked[1]
        self.proto = unpacked[2]
        packet.nextHeader += Ethernet.size
        if self.proto == Ethernet.IP:
            packet.protocols.append("IP")
            packet.ip = IP(packet)
        elif self.proto == Ethernet.ARP:
            packet.protocols.append("ARP")
            packet.arp = ARP(packet)

    @property
    def dstHex(self):
        return macHex(self.dst)

    @property
    def srcHex(self):
        return macHex(self.src)

    def __repr__(self):
        return "Ethernet(dst={0}, src={1}, proto=0x{2:04x})".format(
            self.dstHex, self.srcHex, self.proto)

