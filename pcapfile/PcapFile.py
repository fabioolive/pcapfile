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

from PcapFileHeader import PcapFileHeader
from PcapPacket import PcapPacket

class PcapFile:
    def __init__(self, fileName = None):
        self.fileName = fileName
        self.__packets = []
        if fileName is not None:
            pf = open(fileName, "rb")
            self.header = PcapFileHeader(pf)
            try:
                while True:
                    p = PcapPacket(pf, self.header.linkType)
                    self.__packets.append(p)
            except IOError:
                pass
        else:
            self.header = PcapFileHeader()

    def __len__(self):
        return len(self.__packets)

    def __getitem__(self, k):
        return self.__packets[k]

    def __iter__(self):
        return iter(self.__packets)

    def __repr__(self):
        return "PcapFile(fileName = {0}, header = {1})".format(self.fileName,
            repr(self.header))

