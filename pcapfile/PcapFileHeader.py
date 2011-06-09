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

class PcapFileHeader:
    # FIXME: Little-Endian only at this time
    struct = Struct("<I2H4I")

    # Link types from bpf.h
    linkTypeEthernet = 1

    def __init__(self, fileObj = None):
        if fileObj is not None:
            data = fileObj.read(PcapFileHeader.struct.size)
            if len(data) < PcapFileHeader.struct.size:
                raise IOError("Could not read complete pcap file header")
            unpacked = PcapFileHeader.struct.unpack(data)
        else:
            # Some typical defaults
            unpacked = (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        (self.magic, self.versionMajor, self.versionMinor, self.thisZone,
         self.sigFigs, self.snapLen, self.linkType) = unpacked

    def __repr__(self):
        return ("PcapFileHeader(magic=0x{0:08X}, versionMajor={1}, "
            "versionMinor={2}, thisZone={3}, sigFigs={4}, snapLen={5}, "
            "linkType={6})").format(
                self.magic, self.versionMajor, self.versionMinor,
                self.thisZone, self.sigFigs, self.snapLen, self.linkType)

