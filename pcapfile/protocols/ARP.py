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
from helpers import macHex, ipv4Dotted

class ARP():
    struct = Struct("!HHBBH")
    size = struct.size

    def __init__(self, packet):
        p = packet.nextHeader
        unpacked = ARP.struct.unpack(packet.rawData[p:p+ARP.size])
        self.hType, self.pType, self.hLen, self.pLen, self.op = unpacked
        p += ARP.size
        self.sha = packet.rawData[p:p+self.hLen]
        p += self.hLen
        self.spa = packet.rawData[p:p+self.pLen]
        p += self.pLen
        self.tha = packet.rawData[p:p+self.hLen]
        p += self.hLen
        self.tpa = packet.rawData[p:p+self.pLen]
        packet.nextHeader = p + self.pLen

    @property
    def shaHex(self):
        # FIXME: should not assume Ethernet
        return macHex(self.sha)

    @property
    def thaHex(self):
        # FIXME: should not assume Ethernet
        return macHex(self.tha)

    @property
    def spaStr(self):
         #FIXME: use proper constants
        if self.hType == 1 and self.pType == 0x0800:
            if self.pLen == 4: # IPv4
                return ipv4Dotted(self.spa)

    @property
    def tpaStr(self):
         #FIXME: use proper constants
        if self.hType == 1 and self.pType == 0x0800:
            if self.pLen == 4: # IPv4
                return ipv4Dotted(self.tpa)

    def __repr__(self):
        return ("ARP(hType={0}, pType=0x{1:04x}, hLen={2}, pLen={3}, "
            "op={4}, sha={5}, spa={6}, tha={7}, tpa={8})").format(self.hType,
            self.pType, self.hLen, self.pLen, self.op, self.shaHex,
            self.spaStr, self.thaHex, self.tpaStr)

