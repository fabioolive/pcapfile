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

from PcapPacketHeader import PcapPacketHeader
from PcapFileHeader import PcapFileHeader
from protocols.Ethernet import Ethernet

class PcapPacket:
    def __init__(self, fileObj = None, linkType = 1):
        self.header = PcapPacketHeader(fileObj)
        if fileObj is not None:
            data = fileObj.read(self.header.capLen)
            if len(data) < self.header.capLen:
                raise IOError("Could not read complete packet data")
        else:
            data = r""
        self.rawData = data
        self.nextHeader = 0
        self.protocols = []
        if linkType == PcapFileHeader.linkTypeEthernet:
            self.protocols.append("Ethernet")
            self.ethernet = Ethernet(self)

    def __getitem__(self, k):
        return self.rawData[k]

    def __repr__(self):
        return repr(self.header)

