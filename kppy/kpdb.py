'''
Copyright (C) 2012 Karsten-Kai König <kkoenig@posteo.de>

This file is part of kppy.

kppy is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or at your option) any later version.

kppy is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
kppy.  If not, see <http://www.gnu.org/licenses/>.
'''

from sys import exit
import struct
import hashlib

from Crypto.Cipher import AES

class KPDB(object):
    def __init__(self, filepath=None, masterkey=None):
        self.header = ''
        self.content = ''
        self.signature1 = 0x9AA2D903
        self.signature2 = 0xB54BFB65
        self.enc_flag = 0
        self.version = 0
        self.final_randomseed = ''
        self.enc_iv = ''
        self.num_groups = 0
        self.num_entries = 0
        self.contents_hash = ''
        self.transf_randomseed = ''
        self.key_transf_rounds = 0

        if filepath is not None and masterkey is not None:
            self.load_real(filepath, masterkey)
        elif (filepath is None and masterkey is not None) or (filepath is not \
            None and masterkey is None):
            raise TypeError( 'Missing argument: file path or master key needed '
                             'additionally!' )
            exit(0)

        else:
            pass

    def load_real(self, filepath, masterkey):
        try:
            handler = open(filepath, 'rb')
        except IOError:
            print("Can't open", filepath)
            exit(0)

        try:
            buf = handler.read()

            if len(buf) < 124:
                raise TypeError()
        except IOError:
            print("Can't read", filepath)
            exit(0)
        except TypeError:
            print("Unexpected file size")
            exit(0)
        finally:
            handler.close()

        self.header = buf[:124]
        self.content = buf[124:]

        if not (struct.unpack('<I', self.header[:4])[0] == 0x9AA2D903 and
                struct.unpack('<I', self.header[4:8])[0] == 0xB54BFB65):
            print("Bad signatures!")
            exit(0)

        self.enc_flag = struct.unpack('<I', self.header[8:12])[0]
        self.version = struct.unpack('<I', self.header[12:16])[0]
        self.final_randomseed = struct.unpack('<16s', self.header[16:32])[0]
        self.enc_iv = struct.unpack('<16s', self.header[32:48])[0]
        self.num_groups= struct.unpack('<I', self.header[48:52])[0]
        self.num_entries = struct.unpack('<I', self.header[52:56])[0]
        self.contents_hash = struct.unpack('<32s', self.header[56:88])[0]
        self.transf_randomseed = struct.unpack('<32s', self.header[88:120])[0]
        self.key_transf_rounds = struct.unpack('<I', self.header[120:124])[0]

        if self.version & 0xFFFFFF00 != 0x00030002 & 0xFFFFFF00:
            raise TypeError('Unsupported file version!')
            exit(0)
        elif not self.enc_flag & 2:
            raise TypeError('Unsupported file encryption')
            exit(0)

        final_key = self.transform_key(masterkey)
        decrypted_content = self.cbc_decrypt(final_key)

    def transform_key(self, masterkey):
        hashed_key = hashlib.sha256(masterkey.encode('utf-8')).digest()
        aes = AES.new(self.transf_randomseed, AES.MODE_ECB)

        for i in range(self.key_transf_rounds):
            hashed_key = aes.decrypt(hashed_key)

        hashed_key = hashlib.sha256(hashed_key).digest()
        return hashlib.sha256(self.final_randomseed + hashed_key).digest()

    def cbc_decrypt(self, final_key):
        aes = AES.new(final_key, AES.MODE_CBC, self.enc_iv)
        decrypted_content = aes.decrypt(self.content)
        padding = decrypted_content[-1]
        decrypted_content = decrypted_content[:len(decrypted_content)-padding]
        
        if (len(decrypted_content) > 2147483446) or \
            (len(decrypted_content) == 0 and self.num_groups > 0):
            print("Foo")

        return decrypted_content

