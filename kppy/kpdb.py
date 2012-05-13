# -*- coding: utf-8 -*-
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
from datetime import datetime

from Crypto.Cipher import AES

__doc__ = """This module implements the access to KeePass 1.x-databases."""

class StdGroup(object):
    """StdGroup represents a simple group of a KeePass 1.x database.

    Attributes:
    - id_ is the group id
    - title is the group title
    - image is the image number used in KeePassX
    - parent is the previous group
    - children is a list of all following groups
    - entries is a list of all entries of the group

    """

    def __init__(self):
        self.id_ = None
        self.title = None
        self.image = None
        self.parent = None
        self.children = []
        self.entries = []

class StdEntry(object):
    """StdEntry represents a simple entry of a KeePass 1.x database.
    
    Attributes:
    
    """
    
    def __init__(self):
        self.uuid = None
        self.group_id = None
        self.group = None
        self.image = None
        self.title = None
        self.url = None
        self.username = None
        self.password = None
        self.comment = None
        self.binary_desc = None
        self.creation = None
        self.last_mod = None
        self.last_access = None
        self.expire = None
        self.binary = None

class KPError(Exception):
    """KPError is a exception class to handle exception raised by KPDB.
    
    Usage:
    
    Handle KPError like every else expection. You can print the error message
    via an expection instance.

    Example:

    except KPError as e:
        print(e)
        
    """

    def __init__(self, error):
        self.msg = error

    def __str__(self):
        return self.msg

class KPDB(object):
    """KPDB represents the KeePass 1.x database.
    
    Attributes:
    - groups holds all groups of the database

    Usage:

    You can load a KeePass database by the filename and the passphrase or
    create an empty database (Not yet implemented).

    Example:
    
    from kpdb import KPDB, KPError

    try;
        db = KPDB(filepath, passphrase)
    except KPError as e:
        print(e)

    """


    def __init__(self, filepath=None, masterkey=None):
        self.groups = []
        
        self._entries = []
        self._root_group = StdGroup()
        self._treestate_metastream = {}
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
        
        del masterkey

    def _load(self, filepath, masterkey):
        """This method opens an existing database"""
        
        try:
            handler = open(filepath, 'rb')
        except IOError:
            raise KPError('Can\'t open {0}!'.format(filepath))
            return False

        try:
            buf = handler.read()

            if len(buf) < 124:
                raise KPError('Unexpected file size. It should be more or'
                              'equal 124 bytes but it is {0}!'.format(len(buf)))
                return False
        except IOError:
            raise KPError('Can\'t read {0}!'.format(filepath))
            handler.close()
            return False
        finally:
            handler.close()

        self._header = buf[:124]
        self._crypted_content = buf[124:]
        del buf

        if not (struct.unpack('<I', self._header[:4])[0] == 0x9AA2D903 and
                struct.unpack('<I', self._header[4:8])[0] == 0xB54BFB65):
            raise KPError('Wrong signatures!')
            return False

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
            return False
        elif not self._enc_flag & 2:
            raise KPError('Unsupported file encryption!')
            return False

        final_key = self._transform_key(masterkey)
        decrypted_content = self._cbc_decrypt(final_key)
        del final_key

        if (len(decrypted_content) > 2147483446) or \
            (len(decrypted_content) == 0 and self._num_groups > 0):
            raise KPError("Decryption failed!\nThe key is wrong or the file is "
                          "damaged.")
            del decrypted_content
            return False

        # Implement correct comparison of contents hash and final key

        pos = 0
        levels = []
        cur_group = 0
        group = StdGroup()
        
        while cur_group < self._num_groups:
            field_type = struct.unpack('<H', decrypted_content[:2])[0]
            decrypted_content = decrypted_content[2:]
            pos += 2

            if pos >= len(self._crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                return False

            field_size = struct.unpack('<I', decrypted_content[:4])[0]
            decrypted_content = decrypted_content[4:]
            pos += 4

            if pos >= len(self._crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G2]')
                del decrypted_content
                return False

            b_ret = self._read_group_field(group, levels, field_type,
                                           field_size, decrypted_content)

            if field_type == 0xFFFF and b_ret == True:
                self.groups.append(group)
                group = StdGroup()
                cur_group += 1

            decrypted_content = decrypted_content[field_size:]
            pos += field_size

            if pos >= len(self._crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                return False

        cur_entry = 0
        entry = StdEntry()

        while cur_entry < self._num_entries:
            field_type = struct.unpack('<H', decrypted_content[:2])[0]
            decrypted_content = decrypted_content[2:]
            pos += 2

            if pos >= len(self._crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                return False

            field_size = struct.unpack('<I', decrypted_content[:4])[0]
            decrypted_content = decrypted_content[4:]
            pos +=4

            if pos >= len(self._crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G2]')
                del decrypted_content
                return False

            b_ret = self._read_entry_field(entry, field_type, field_size,
                                      decrypted_content)

            if field_type == 0xFFFF and b_ret == True:
                self._entries.append(entry)
                if not entry.group_id:
                    pass
                
                entry = StdEntry()
                cur_entry += 1

            decrypted_content = decrypted_content[field_size:]
            pos += field_size

            if pos >= len(self._crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                return False

        if not self._create_group_tree(levels):
            raise KPError('Invalid group tree.')
            del decrypted_content
            return false

        del decrypted_content

        has_V4_icons_metastream = False
        for i in range(len(self._entries)):
            if self._is_metastream(self._entries[i]) and \
                self._entries[i].comment == "KPX_CUSTOM_ICONS_4":
                has_V4_icons_metastream = True
                break

        i = 0
        while i < len(self._entries):
            if self._is_metastream(self._entries[i]):
                if not self._parse_metastream(self._entries[i],
                    has_V4_icons_metastream):
                    unknown_metastreams.append(self._entries[i])
                    i += 1
                del self._entries[i]
            i += 1
                

    def _transform_key(self, masterkey):
        """This method creates the key to decrypt the database"""

        hashed_key = hashlib.sha256(masterkey.encode()).digest()
        aes = AES.new(self._transf_randomseed, AES.MODE_ECB)

        for i in range(self._key_transf_rounds):
            hashed_key = aes.encrypt(hashed_key)

        hashed_key = hashlib.sha256(hashed_key).digest()
        return hashlib.sha256(self._final_randomseed + hashed_key).digest()

    def _cbc_decrypt(self, final_key):
        """This method decrypts the database"""

        aes = AES.new(final_key, AES.MODE_CBC, self._enc_iv)
        decrypted_content = aes.decrypt(self._crypted_content)
        padding = decrypted_content[-1]
        decrypted_content = decrypted_content[:len(decrypted_content)-padding]
        
        return decrypted_content

    def _read_group_field(self, group, levels, field_type, field_size,  
                          decrypted_content):
        """This method handles the different fields of a group"""

        if field_type == 0x0000:
            # Ignored (commentar block)
            pass
        elif field_type == 0x0001:
            group.id_ = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0002:
            group.title = str(struct.unpack('<{0}s'.format(field_size-1),
                                        decrypted_content[:field_size-1])[0],
                                        'utf-8')
            decrypted_content = decrypted_content[1:]
        elif field_type == 0x0003:
            # Not implemented by KeePassX but is defined by the original
            # KeePass standard
            # Will be implemented in a later release
            pass
        elif field_type == 0x0004:
            # Not implemented by KeePassX but is defined by the original
            # KeePass standard
            # Will be implemented in a later release
            pass
        elif field_type == 0x0005:
            # Not implemented by KeePassX but is defined by the original
            # KeePass standard
            # Will be implemented in a later release
            pass
        elif field_type == 0x0006:
            # Not implemented by KeePassX but is defined by the original
            # KeePass standard
            # Will be implemented in a later release
            pass
        elif field_type == 0x0007:
            group.image = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0008:
            level = struct.unpack('<H', decrypted_content[:2])[0]
            levels.append(level)
        elif field_type == 0x0009:
            # Not implemented by KeePassX but is defined by the original
            # KeePass standard
            # Will be implemented in a later release
            pass
        elif field_type == 0xFFFF:
            pass
        else:
            return False
        return True

    def _read_entry_field(self, entry, field_type, field_size,
                          decrypted_content):
        """This method handles the different fields of an entry"""

        if field_type == 0x0000:
            # Ignored
            pass
        elif field_type == 0x0001:
            # Later
            pass
        elif field_type == 0x0002:
            entry.group_id = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0003:
            entry.image = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0004:
            entry.title = str(struct.unpack('<{0}s'.format(field_size-1),
                                        decrypted_content[:field_size-1])[0],
                                        'utf-8')
            decrypted_content = decrypted_content[1:]
        elif field_type == 0x0005:
            entry.url = str(struct.unpack('<{0}s'.format(field_size-1),
                                        decrypted_content[:field_size-1])[0],
                                        'utf-8')
            decrypted_content = decrypted_content[1:]
        elif field_type == 0x0006:
            entry.username = str(struct.unpack('<{0}s'.format(field_size-1),
                                        decrypted_content[:field_size-1])[0],
                                         'utf-8')
            decrypted_content = decrypted_content[1:]
        elif field_type == 0x0007:
            entry.password = str(struct.unpack('<{0}s'.format(field_size-1),
                                        decrypted_content[:field_size-1])[0],
                                        'utf-8')
        elif field_type == 0x0008:
            entry.comment = str(struct.unpack('<{0}s'.format(field_size-1),
                                        decrypted_content[:field_size-1])[0],
                                        'utf-8')
        elif field_type == 0x0009:
            date = self._get_date(decrypted_content)
            entry.creation = date
        elif field_type == 0x000A:
            date = self._get_date(decrypted_content)
            entry.last_mod = date
        elif field_type == 0x000B:
            date = self._get_date(decrypted_content)
            entry.last_access = date
        elif field_type == 0x000C:
            date = self._get_date(decrypted_content)
            entry.expire = date
        elif field_type == 0x000D:
            entry.binary_desc = str(struct.unpack('<{0}s'.format(field_size-1),
                                       decrypted_content[:field_size-1])[0],
                                       'utf-8')
        elif field_type == 0x000E:
            entry.binary = decrypted_content[:field_size-1]
        elif field_type == 0xFFFF:
            pass
        else:
            return False
        return True

    def _get_date(self, decrypted_content):
        date_field = struct.unpack('<5B', decrypted_content[:5])
        dw1 = date_field[0]
        dw2 = date_field[1]
        dw3 = date_field[2]
        dw4 = date_field[3]
        dw5 = date_field[4]

        y = (dw1 << 6) | (dw2 >> 2)
        mon = ((dw2 & 0x03) << 2) | (dw3 >> 6)
        d = (dw3 >> 1) & 0x1F
        h = ((dw3 & 0x01) << 4) | (dw4 >> 4)
        min_ = ((dw4 & 0x0F) << 2) | (dw5 >> 6)
        s = dw5 & 0x3F
        return datetime(y, mon, d, h, min_, s)

    def _create_group_tree(self, levels):
        if levels[0] != 0: return false;
        
        for i in range(len(self.groups)):
            if(levels[i] == 0):
                self.groups[i].parent = self._root_group
                self.groups[i].index = len(self._root_group.children)
                self._root_group.children.append(self.groups[i])
                continue

            for j in range(i-1, -1):
                if Levels[j] < Levels[i]:
                    if Levels[i]-Levels[j] != 1: return false;
                    
                    self.groups[i].parent = self.groups[j]
                    self.groups[i].index = len(groups[j].children)
                    self.groups[i].parent.children.append(self.groups[i])
                    break
                if j == 0: return false;
            
        for e in range(len(self._entries)):
            for g in range(len(self.groups)):
                if self._entries[e].group_id == self.groups[g].id_:
                    self.groups[g].entries.append(self._entries[e])
                    self._entries[e].group = self.groups[g]
                    # from original KeePassX-code, but what does it do?
                    self._entries[e].index = 0
                    
        return True

    def _is_metastream(self, entry):
        if len(entry.binary) == 0 or entry.comment == "" or \
            entry.binary_desc != "bin-stream" or entry.title != "Meta-Info" or \
            entry.username != "SYSTEM" or entry.url != "$" or \
            entry.image != 0:
            return False
        else:
            return True

    def _parse_metastream(self, entry, has_V4_icons_metastream):
        print("Found Metastream: "+entry.comment)
        
        if entry.comment == "KPX_GROUP_TREE_STATE":
            self._parse_group_treestate_metastream(entry.binary)
            return True
        elif entry.comment == "KPX_CUSTOM_ICONS_4":
            self._parse_custom_icons_metastream(entry.binary)
            return True
        elif entry.comment == "KPX_CUSTOM_ICONS_3":
            if not has_V4_icons_metastream:
                self._parse_custom_icons_metastream_V3(entry.binary)
            return True
        elif entry.comment == "KPX_CUSTOM_ICONS_2":
            print("Removed old CuIcMeSt v2")
            return True
        elif entry.comment == "KPX_CUSTOM_ICONS":
            print("Removed old CuIcMeSt v1")
            return True
        else:
            return False

    def _parse_group_treestate_metastream(self, binary):
        if len(binary < 4):
            raise KPError('Discarded metastream KPX_GROUP_TREE_STATE because of a'
                   'parsing error.')
            return
        num = struct.unpack('<I', binary[:4])[0]
        if num*5 != len(binary)-4:
            raise KPError('Discarded metastream KPX_GROUP_TREE_STATE because of a'
                   'parsing error.')
            return

        self._treestate_metastream.clear

        for i in range(num):
            group_id = struct.unpack('<I', binary[5*i:4+5*i])[0]
            is_expanded = struct.unpack('<?', binary[4+5*i:8+5*i])[0]
            self._treestate_metastream.insert(group_id, is_expanded)

        return
            
    def _parse_custom_icons_metastream(self, binary):
        pass

    def _parse_custom_icons_metastream_V3(self, binary):
        pass
