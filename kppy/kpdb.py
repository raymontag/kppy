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

import struct
import hashlib

from Crypto.Cipher import AES

class StdGroup(object):
    def __init__(self):
        self.id_ = None
        self.title = None
        self.index = None
        self.image = None
        self.parent = None
        self.handle = None
        self.children = []
        self.entries = []

class KPError(Exception):
    def __init__(self, error):
        self.msg = error

    def __str__(self):
        return self.msg

class KPDB(object):
    def __init__(self, filepath=None, masterkey=None):
        self.groups = []
        
        self._root_group = StdGroup()
        self._header = b''
        self._crypted_content = b''
        self._signature1 = 0x9AA2D903
        self._signature2 = 0xB54BFB65
        self._enc_flag = 0
        self._version = 0
        self._final_randomseed = ''
        self._enc_iv = ''
        self._num_groups = 0
        self._num_entries = 0
        self._contents_hash = ''
        self._transf_randomseed = ''
        self._key_transf_rounds = 0

        if filepath is not None and masterkey is not None:
            self._load(filepath, masterkey)
        elif (filepath is None and masterkey is not None) or (filepath is not \
            None and masterkey is None):
            raise KPError('Missing argument: file path or master key needed '
                          'additionally!')
        else:
            pass

    def _load(self, filepath, masterkey):
        try:
            handler = open(filepath, 'rb')
        except IOError:
            raise KPError('Can\'t open {0}!'.format(filepath))

        try:
            buf = handler.read()

            if len(buf) < 124:
                raise KPError('Unexpected file size. It should be more or'
                              'equal 124 bytes but it is !'.format(len(buf)))
        except IOError:
            raise KPError('Can\'t read {0}!'.format(filepath))
        finally:
            handler.close()

        self._header = buf[:124]
        self._crypted_content = buf[124:]

        if not (struct.unpack('<I', self._header[:4])[0] == 0x9AA2D903 and
                struct.unpack('<I', self._header[4:8])[0] == 0xB54BFB65):
            raise KPError('Wrong signatures!')

        self._enc_flag = struct.unpack('<I', self._header[8:12])[0]
        self._version = struct.unpack('<I', self._header[12:16])[0]
        self._final_randomseed = struct.unpack('<16s', self._header[16:32])[0]
        self._enc_iv = struct.unpack('<16s', self._header[32:48])[0]
        self._num_groups= struct.unpack('<I', self._header[48:52])[0]
        self._num_entries = struct.unpack('<I', self._header[52:56])[0]
        self._contents_hash = struct.unpack('<32s', self._header[56:88])[0]
        self._transf_randomseed = struct.unpack('<32s', self._header[88:120])[0]
        self._key_transf_rounds = struct.unpack('<I', self._header[120:124])[0]

        if self._version & 0xFFFFFF00 != 0x00030002 & 0xFFFFFF00:
            raise KPError('Unsupported file version!')
        elif not self._enc_flag & 2:
            raise KPError('Unsupported file encryption!')

        final_key = self._transform_key(masterkey)
        decrypted_content = self._cbc_decrypt(final_key)

        #Implement correct comparison of contents hash and final key

        pos = 0
        levels = []
        cur_group = 0
        group = StdGroup()
        
        while cur_group < self._num_groups:
            field_type = struct.unpack('<H', decrypted_content[:2])[0]
            decrypted_content = decrypted_content[2:]
            pos+= 2

            if pos >= len(self._crypted_content):
                raise KPError('Unexpected error: Offset is out of range.[G1]')

            field_size = struct.unpack('<I', decrypted_content[:4])[0]
            decrypted_content = decrypted_content[4:]
            pos += 4

            if pos >= len(self._crypted_content):
                raise KPError('Unexpected error: Offset is out of range.[G2]')

            b_ret = self._read_group_field(group, levels, field_type,
                                      decrypted_content)

            if field_type == 0xFFFF and b_ret == True:
                self.groups.append(group)
                cur_group += 1

            decrypted_content = decrypted_content[field_size:]
            pos += field_size

            if pos >= len(self._crypted_content):
                raise KPError('Unexpected error: Offset is out of range.[G1]')

    def _transform_key(self, masterkey):
        hashed_key = hashlib.sha256(masterkey.encode()).digest()
        aes = AES.new(self._transf_randomseed, AES.MODE_ECB)

        for i in range(self._key_transf_rounds):
            hashed_key = aes.encrypt(hashed_key)

        hashed_key = hashlib.sha256(hashed_key).digest()
        return hashlib.sha256(self._final_randomseed + hashed_key).digest()

    def _cbc_decrypt(self, final_key):
        aes = AES.new(final_key, AES.MODE_CBC, self._enc_iv)
        decrypted_content = aes.decrypt(self._crypted_content)
        padding = decrypted_content[-1]
        decrypted_content = decrypted_content[:len(decrypted_content)-padding]
        
        if (len(decrypted_content) > 2147483446) or \
            (len(decrypted_content) == 0 and self._num_groups > 0):
            raise KPError("Decryption failed!\nThe key is wrong or the file is "
                          "damaged.")
            
        return decrypted_content

    def _read_group_field(self, group, levels, field_type, decrypted_content):
        if field_type == 0x0001:
            group.id_ = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0002:
            pass
        elif field_type == 0x0003:
            pass
        elif field_type == 0x0004:
            pass
        elif field_type == 0x0005:
            pass
        elif field_type == 0x0006:
            pass
        elif field_type == 0x0007:
            group.image = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0008:
            level = struct.unpack('<H', decrypted_content[:2])[0]
            levels.append(level)
        elif field_type == 0x0009:
            pass
        elif field_type == 0xFFFF:
            pass
        else:
            return False
        return True
