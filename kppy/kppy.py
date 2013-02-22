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
from datetime import datetime
from os import remove, path

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


__doc__ = """This module implements the access to KeePass 1.x-databases."""

class StdGroup(object):
    """StdGroup represents a simple group of a KeePass 1.x database.
    
    Attributes:
    - id_ is the group id (unsigned int)
    - title is the group title (string)
    - image is the image number used in KeePassX (unsigned int)
    - level is needed to create the group tree (unsigned int)
    - parent is the previous group (StdGroup)
    - children is a list of all following groups (list of StdGroups)
    - entries is a list of all entries of the group (list of StdEntrys)
    - db is the database which holds the group (KPDB)
    
    """

    def __init__(self, id_ = None, title = None, image = 1, db = None,
                 level = 0, parent = None, children = [], entries = [],
                 creation = None, last_mod = None, last_access = None,
                 expire = None, flags = None):
        """Initialize a StdGroup-instance.

        It's recommended to use create_group of KPDB and not this directly.

        """

        self.id_ = id_
        self.title = title
        self.image = image
        self.level = level
        self.creation = creation
        self.last_mod = last_mod
        self.last_access = last_access
        self.expire = expire
        self.flags = flags
        self.parent = parent
        self.children = list(children)
        self.entries = list(entries)
        self.db = db

    def set_title(self, title = None):
        """This method is used to change a group title.

        title must be a string.

        """
        
        if title is None or type(title) is not str:
            raise KPError("Need a new title!")
            return False
        else:
            self.title = title
            self.last_mod = datetime.now().replace(microsecond = 0)
            return True

    def set_image(self, image = None):
        """This method is used to change the image number of a group.

        image must be an unsigned int >0.

        """
        
        if image is None or type(image) is not int or image < 1:
            raise KPError("Need a group and an image number!")
            return False
        else:
            self.image = image
            self.last_mod = datetime.now().replace(microsecond = 0)
            return True

    def set_expire(self, y = 2999, mon = 12, d = 28, h = 23, min_ = 59, 
                   s = 59):
        """This method is used to change the expire date of a group

            - y is the year between 1 and 9999 inclusive
            - mon is the month between 1 and 12
            - d is a day in the given month
            - h is a hour between 0 and 23
            - min_ is a minute between 0 and 59
            - s is a second between 0 and 59

        The special date 2999-12-28 23:59:59 means that group expires never. If
        only an uuid is given the expire date will set to this one.
        
        """

        if type(y) is not int or type(mon) is not int or type(d) is not int or \
            type(h) is not int or type(min_) is not int or type(s) is not int:
            raise KPError("Date variables must be integers")
            return False
        elif y > 9999 or y < 1 or mon > 12 or mon < 1 or d > 31 or d < 1 or \
            h > 23 or h < 0 or min_ > 59 or min_ < 0 or s > 59 or s < 0:
            raise KPError("No legal date")
            return False
        elif ((mon == 1 or mon == 3 or mon == 5 or mon == 7 or mon == 8 or \
             mon == 10 or mon == 12) and d > 31) or ((mon == 4 or mon == 6 or \
             mon == 9 or mon == 11) and d > 30) or (mon == 2 and d > 28):
            raise KPError("Given day doesn't exist in given month")
            return False
        else:
            self.expire = datetime(y, mon, d, h, min_, s)
            self.last_mod = datetime.now().replace(microsecond = 0)
            return True

    def move_group(self, parent):
        """calls self.db.move_group"""

        return self.db.move_group(self, parent)

    def move_group_in_parent(self, index):
        """calls move_group_in_parent"""

        return self.db.move_group_in_parent(self, index)

    def remove_group(self):
        """This method calls remove_group of the holding db"""

        return self.db.remove_group(self)

    def create_entry(self, title='', image=1, url='', username='', password='',
                      comment='', y=2999, mon=12, d=28, h=23, min_=59, s=59):
        """This method creates an entry in this group.

        Compare to StdEntry for information about the arguments.

        One of the following arguments is needed:

        - title
        - url
        - username
        - password
        - comment
        
        """

        return self.db.create_entry(self, title, image, url, username, 
                                    password, comment, y, mon, d, h, min_, s)

class StdEntry(object):
    """StdEntry represents a simple entry of a KeePass 1.x database.
    
    Attributes:
        - uuid is an "Universal Unique ID", that is it identifies the entry (16 bytes string)
        - group_id is the id of the holding group (unsigned int)
        - group is the holding StdGroup instance
        - image is the image number (unsigned int)
        - title is the entry title (string)
        - url is an url to a website where the login information of this entry (string)
          can be used
        - username is an username (string)
        - password is the password (string)
        - creation is the creation date of this entry (datetime-instance)
        - last_mod is the date of the last modification (datetime-instance)
        - last_access is the date of the last access (datetime-instance)
        - expire is the date when the entry should expire (datetime-instance)
        - comment is a comment string
    """ 

    def __init__(self, group_id = None, group = None,
                 image = 1, title = None, url = None, username = None,
                 password = None, comment = None, 
                 creation = None, last_mod = None, last_access = None, 
                 expire = None, uuid = None, binary_desc = None,
                 binary = None):
        """Initialize a StdEntry-instance.

        It's recommended to use create_entry of StdGroup or KPDB.

        """

        self.uuid = uuid
        self.group_id = group_id
        self.group = group
        self.image = image
        self.title = title
        self.url = url
        self.username = username
        self.password = password
        self.comment = comment
        self.binary_desc = binary_desc
        self.creation = creation
        self.last_mod = last_mod
        self.last_access = last_access
        self.expire = expire
        self.binary = binary

    def set_title(self, title = None):
        """This method is used to change an entry title.

        A new title string is needed.

        """

        if title is None or type(title) is not str:
            raise KPError("Need a new title.")
            return False
        else:
            self.title = title
            self.last_mod = datetime.now().replace(microsecond=0)
            return True
        
    def set_image(self, image = None):
        """This method is used to set the image number.

        image must be an unsigned int.

        """
        
        if image is None or type(image) is not int:
            raise KPError("Need a new image number")
            return False
        else:
            self.image = image
            self.last_mod = datetime.now().replace(microsecond=0)
            return True
        
    def set_url(self, url = None):
        """This method is used to set the url.

        url must be a string.

        """
                
        if url is None or type(url) is not str:
            raise KPError("Need a new image number")
            return False
        else:
            self.url = url
            self.last_mod = datetime.now().replace(microsecond=0)
            return True

    def set_username(self, username = None):
        """This method is used to set the username.

        username must be a string.

        """
        
        if username is None or type(username) is not str:
            raise KPError("Need a new image number")
            return False
        else:
            self.username = username
            self.last_mod = datetime.now().replace(microsecond=0)
            return True
        
    def set_password(self, password = None):
        """This method is used to set the password.

        password must be a string.

        """
        
        if password is None or type(password) is not str:
            raise KPError("Need a new image number")
            return False
        else:
            self.password = password
            self.last_mod = datetime.now().replace(microsecond=0)
            return True
        
    def set_comment(self, comment = None):
        """This method is used to the the comment.

        comment must be a string.

        """
        
        if comment is None or type(comment) is not str:
            raise KPError("Need a new image number")
            return False
        else:
            self.comment = comment
            self.last_mod = datetime.now().replace(microsecond=0)
            return True

    def set_expire(self, y = 2999, mon = 12, d = 28, h = 23, min_ = 59, 
                   s = 59):
        """This method is used to change the expire date of an entry.

            - y is the year between 1 and 9999 inclusive
            - mon is the month between 1 and 12
            - d is a day in the given month
            - h is a hour between 0 and 23
            - min_ is a minute between 0 and 59
            - s is a second between 0 and 59

        The special date 2999-12-28 23:59:59 means that  expires never. If
        only an uuid is given the expire date will set to this one.
        
        """

        if type(y) is not int or type(mon) is not int or type(d) is not int or \
            type(h) is not int or type(min_) is not int or type(s) is not int:
            raise KPError("Date variables must be integers")
            return False
        elif y > 9999 or y < 1 or mon > 12 or mon < 1 or d > 31 or d < 1 or \
            h > 23 or h < 0 or min_ > 59 or min_ < 0 or s > 59 or s < 0:
            raise KPError("No legal date")
            return False
        elif ((mon == 1 or mon == 3 or mon == 5 or mon == 7 or mon == 8 or \
             mon == 10 or mon == 12) and d > 31) or ((mon == 4 or mon == 6 or \
             mon == 9 or mon == 11) and d > 30) or (mon == 2 and d > 28):
            raise KPError("Given day doesn't exist in given month")
            return False
        else:
            self.expire = datetime(y, mon, d, h, min_, s)
            self.last_mod = datetime.now().replace(microsecond = 0)
            return True

    def move_entry(self, group = None):
        """This method moves the entry to another group.

        group must be a valid StdGroup-instance.

        """

        return self.group.db.move_entry(self, group)

    def move_entry_in_group(self, index):
        """This method moves the entry to another position in the group.
        
        index must be a valid index for self.group.entries.

        """ 

        return self.group.db.move_entry_in_group(self, index)

    def remove_entry(self):
        """This method removes this entry."""

        return self.group.db.remove_entry(self)

class KPError(Exception):
    """KPError is a exception class to handle exception raised by KPDB.
    
    Usage:
    
    Handle KPError like every else expection. You can print the error message
    via an expection instance.
    
    Example:
    
    try:
        ...
    except KPError as e:
        print(e)
        
    """

    def __init__(self, error):
        self.msg = error

    def __str__(self):
        return ("KPError: "+self.msg)

class KPDB(object):
    """KPDB represents the KeePass 1.x database.
    
    Attributes:
    - groups holds all groups of the database. (list of StdGroups)
    - read_only declares if the file should be read-only or not (bool)
    - filepath holds the path of the database (string)
    - password is the passphrase to encrypt and decrypt the database (string)
    - keyfile is the path to a keyfile (string)
    
    Usage:
    
    You can load a KeePass database by the filename and the passphrase or
    create an empty database. It's also possible to open the database read-only
    and to create a new one.
    
    Example:
    
    from kppy import KPDB, KPError
    
    try;
        db = KPDB(filepath, passphrase)
    except KPError as e:
        print(e)
    
    """

    def __init__(self, filepath=None, password=None, keyfile=None, 
                 read_only=False, new = False):
        """ Initialize a new or an existing database.

        If a 'filepath' and a 'masterkey' is passed 'load' will try to open
        a database. If 'True' is passed to 'read_only' the database will open
        read-only. It's also possible to create a new one, just pass 'True' to
        new. This will be ignored if a filepath and a masterkey is given this
        will be ignored.
        
        """
        
        
        if ((filepath is None and (password is not None or 
            keyfile is not None)) or filepath is not None and
            (password is None and keyfile is None)):
            raise KPError('Missing argument: file path, password or keyfile '
                          'needed additionally to open an existing database!')
            return
        elif type(read_only) is not bool or type(new) is not bool:
            raise KPError('read_only and new must be bool')
            return
        elif ((filepath is not None and type(filepath) is not str) or
              (type(password) is not str and password is not None) or
              (type(keyfile) is not str and keyfile is not None)):
            raise KPError('filepath, masterkey and keyfile must be a string')
            return
        elif (filepath is None and password is None and keyfile is None and 
              new is False):
            raise KPError('Either an existing database should be opened or '
                          'a new should be created.')
            return

        self.groups = []
        self.read_only = read_only
        self.filepath = filepath
        self.password = password
        self.keyfile = keyfile

        # This are attributes that are needed internally. You should not
        # change them directly, it could damage the database!
        self._entries = []
        self._root_group = StdGroup()
        self._group_order = []
        self._entry_order = []
        self._unsupported_g_fields = []
        self._unsupported_e_fields = []
        self._signature1 = 0x9AA2D903
        self._signature2 = 0xB54BFB65
        self._enc_flag = 2
        self._version = 0x00030002
        self._final_randomseed = ''
        self._enc_iv = ''
        self._num_groups = 1
        self._num_entries = 0
        self._contents_hash = ''
        self._transf_randomseed = Random.get_random_bytes(32)
        self._key_transf_rounds = 50000

        # Load an existing database
        if (filepath is not None and (password is not None or 
            keyfile is not None)):
            self.load()
        # Due to the design of KeePass, at least one group is needed.
        elif new is True:
            self._group_order = [("id", 1), (1,4), (2,9), (7,4), (8,2),
                                 (0xFFFF, 0)]
            group = StdGroup(1, 'Internet', 1, self, parent = self._root_group)
            self._root_group.children.append(group)
            self.groups.append(group)
        
    def load(self):
        """This method opens an existing database.

        self.password/self.keyfile and self.filepath must be set.
        
        """

        if self.password is None and self.keyfile is None:
            raise KPError('Need a password or keyfile')
            return False
        elif self.filepath is None:
            raise KPError('Can only load an existing database!')
            return False
        
        # Open the file
        try:
            handler = open(self.filepath, 'rb')
        except IOError:
            raise KPError('Can\'t open {0}!'.format(self.filepath))
            return False

        # Read the file and close it finally
        try:
            buf = handler.read()
            
            # There should be a header at least
            if len(buf) < 124:
                raise KPError('Unexpected file size. It should be more or'
                              'equal 124 bytes but it is {0}!'.format(len(buf)))
                return False
        except IOError:
            raise KPError('Can\'t read {0}!'.format(self.filepath))
            handler.close()
            return False
        finally:
            handler.close()
        
        # The header is 124 bytes long, the rest is content
        header = buf[:124]
        crypted_content = buf[124:]
        del buf
        
        # The header holds two signatures
        if not (struct.unpack('<I', header[:4])[0] == 0x9AA2D903 and
                struct.unpack('<I', header[4:8])[0] == 0xB54BFB65):
            raise KPError('Wrong signatures!')
            del crypted_content
            del header
            return False

        # Unpack the header
        self._enc_flag = struct.unpack('<I', header[8:12])[0]
        self._version = struct.unpack('<I', header[12:16])[0]
        self._final_randomseed = struct.unpack('<16s', header[16:32])[0]
        self._enc_iv = struct.unpack('<16s', header[32:48])[0]
        self._num_groups= struct.unpack('<I', header[48:52])[0]
        self._num_entries = struct.unpack('<I', header[52:56])[0]
        self._contents_hash = struct.unpack('<32s', header[56:88])[0]
        self._transf_randomseed = struct.unpack('<32s', header[88:120])[0]
        self._key_transf_rounds = struct.unpack('<I', header[120:124])[0]
        del header

        # Check if the database is supported
        if self._version & 0xFFFFFF00 != 0x00030002 & 0xFFFFFF00:
            raise KPError('Unsupported file version!')
            del crypted_content
            return False
        #Actually, only AES is supported.
        elif not self._enc_flag & 2:
            raise KPError('Unsupported file encryption!')
            del crypted_content
            return False
        
        if self.password is None:
            masterkey = self._get_filekey()
        elif self.password is not None and self.keyfile is not None:
            passwordkey = self._get_passwordkey()
            filekey = self._get_filekey()
            sha = SHA256.new()
            sha.update(passwordkey+filekey)
            masterkey = sha.digest()
        else:
            masterkey = self._get_passwordkey()

        # Create the key that is needed to...
        final_key = self._transform_key(masterkey)
        # ...decrypt the content
        decrypted_content = self._cbc_decrypt(final_key, crypted_content)

        # Check if decryption failed
        if ((len(decrypted_content) > 2147483446) or
            (len(decrypted_content) == 0 and self._num_groups > 0)):
            raise KPError("Decryption failed!\nThe key is wrong or the file is"
                          " damaged.")
            del decrypted_content
            del crypted_content
            return False

        sha_obj = SHA256.new()
        sha_obj.update(decrypted_content)
        if not self._contents_hash == sha_obj.digest():
            raise KPError("Hash test failed.\nThe key is wrong or the file is "
                          "damaged.")
            return False
        del masterkey
        del final_key

        # Read out the groups
        pos = 0
        levels = []
        cur_group = 0
        group = StdGroup()

        while cur_group < self._num_groups:
            # Every group is made up of single fields
            field_type = struct.unpack('<H', decrypted_content[:2])[0]
            decrypted_content = decrypted_content[2:]
            pos += 2

            # Check if offset is alright
            if pos >= len(crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                del crypted_content
                return False
            
            field_size = struct.unpack('<I', decrypted_content[:4])[0]
            decrypted_content = decrypted_content[4:]
            pos += 4
            
            if pos >= len(crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G2]')
                del decrypted_content
                del crypted_content
                return False

            # Finally read out the content
            b_ret = self._read_group_field(group, levels, field_type,
                                           field_size, decrypted_content)

            # If the end of a group is reached append it to the groups array
            if field_type == 0xFFFF and b_ret == True:
                group.db = self
                self.groups.append(group)
                group = StdGroup()
                cur_group += 1
            
            decrypted_content = decrypted_content[field_size:]

            if pos >= len(crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                del crypted_content
                return False

        # Now the same with the entries
        cur_entry = 0
        entry = StdEntry()
        
        while cur_entry < self._num_entries:
            field_type = struct.unpack('<H', decrypted_content[:2])[0]
            decrypted_content = decrypted_content[2:]
            pos += 2
             
            if pos >= len(crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                del crypted_content
                return False
            
            field_size = struct.unpack('<I', decrypted_content[:4])[0]
            decrypted_content = decrypted_content[4:]
            pos +=4
            
            if pos >= len(crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G2]')
                del decrypted_content
                del crypted_content
                return False
            
            b_ret = self._read_entry_field(entry, field_type, field_size,
                                      decrypted_content)
            
            if field_type == 0xFFFF and b_ret == True:
                self._entries.append(entry)
                if entry.group_id is None:
                    raise KPError("Found entry without group!")
                    del decrypted_content
                    del crypted_content
                    return False

                entry = StdEntry()
                cur_entry += 1
            
            decrypted_content = decrypted_content[field_size:]
            pos += field_size
            
            if pos >= len(crypted_content)+124:
                raise KPError('Unexpected error: Offset is out of range.[G1]')
                del decrypted_content
                del crypted_content
                return False

        if self._create_group_tree(levels) is False:
            del decrypted_content
            del crypted_content
            return False

        del decrypted_content
        del crypted_content

        try:
            handler = open(self.filepath+'.lock', 'w')
            handler.write('')
        finally:
            handler.close()

        return True

    def save(self, filepath = None, password = None, keyfile = None):
        """This method saves the database.

        It's possible to parse a data path to an alternative file.

        """
        
        if (password is None and keyfile is not None and keyfile != "" and
            type(keyfile) is str):
            self.keyfile = keyfile
        elif (keyfile is None and password is not None and password != "" and
              type(password is str)):
            self.password = password
        elif (keyfile is not None and password is not None and
              keyfile != "" and password != "" and type(keyfile) is str and
              type(password) is str):
            self.keyfile = keyfile
            self.password = password

        if self.read_only:
            raise KPError("The database has been opened read-only.")
            return False
        elif ((self.password is None and self.keyfile is None) or 
              (filepath is None and self.filepath is None) or 
              (keyfile == "" and password == "")):
            raise KPError("Need a password/keyfile and a filepath to save the "
                          "file.")
            return False
        elif ((type(self.filepath) is not str and self.filepath is not None) or
              (type(self.password) is not str and self.password is not None) or
              (type(self.keyfile) is not str and self.keyfile is not None)):
            raise KPError("filepath, password and keyfile  must be strings.")
            return False
        elif self._num_groups == 0:
            raise KPError("Need at least one group!")
            return False
        
        content = bytearray()

        # First, read out all groups
        for i in self.groups:
            # Get the packed bytes
            # j stands for a possible field type
            for j in range(1,10):
                ret_save = self._save_group_field(j, i)
                # The field type and the size is always in front of the data
                if ret_save is not False:
                    content += struct.pack('<H', j)
                    content += struct.pack('<I', ret_save[0])
                    content += ret_save[1]
            # End of field
            content += struct.pack('<H', 0xFFFF)
            content += struct.pack('<I', 0) 

        # Same with entries
        for i in self._entries:
            for j in range(1, 15):
                ret_save = self._save_entry_field(j, i)
                if ret_save is not False:
                    content += struct.pack('<H', j)
                    content += struct.pack('<I', ret_save[0])
                    content += ret_save[1]
            content += struct.pack('<H', 0xFFFF)
            content += struct.pack('<I', 0)

        # Generate new seed and new vector; calculate the new hash
        self._final_randomseed = Random.get_random_bytes(16)
        self._enc_iv = Random.get_random_bytes(16)
        sha_obj = SHA256.new()
        sha_obj.update(bytes(content))
        self._contents_hash = sha_obj.digest()
        del sha_obj

        # Pack the header
        header = bytearray()
        header += struct.pack('<I', 0x9AA2D903)
        header += struct.pack('<I', 0xB54BFB65)
        header += struct.pack('<I', self._enc_flag)
        header += struct.pack('<I', self._version)
        header += struct.pack('<16s', self._final_randomseed)
        header += struct.pack('<16s', self._enc_iv)
        header += struct.pack('<I', self._num_groups)
        header += struct.pack('<I', self._num_entries)
        header += struct.pack('<32s', self._contents_hash)
        header += struct.pack('<32s', self._transf_randomseed)
        header += struct.pack('<I', self._key_transf_rounds)

        # Finally encrypt everything...
        if self.password is None:
            masterkey = self._get_filekey()
        elif self.password is not None and self.keyfile is not None:
            passwordkey = self._get_passwordkey()
            filekey = self._get_filekey()
            sha = SHA256.new()
            sha.update(passwordkey+filekey)
            masterkey = sha.digest()
        else:
            masterkey = self._get_passwordkey()
        final_key = self._transform_key(masterkey)
        encrypted_content = self._cbc_encrypt(content, final_key)
        del content
        del masterkey
        del final_key
        
        # ...and write it out
        if filepath is not None:
            try:
                handler = open(filepath, "wb")
            except IOError:
                raise KPError("Can't open {0}".format(filepath))
                return False
            if self.filepath is None:
                self.filepath = filepath
        elif filepath is None and self.filepath is not None:
            try:
                handler = open(self.filepath, "wb")
            except IOError:
                raise KPError("Can't open {0}".format(self.filepath))
                return False
        else:
            raise KPError("Need a filepath.")
            return False

        try:
            handler.write(header+encrypted_content)
        except IOError:
            raise KPError("Can't write to file.")
            return False
        finally:
            handler.close()
        
        if not path.isfile(self.filepath+".lock"):
            try:
                lock= open(self.filepath+".lock", "w")
                lock.write('')
            except IOError:
                raise KPError("Can't create lock-file {0}".format(self.filepath
                                                                  +".lock"))
                return False
            else:
                lock.close()
        return True

    def close(self):
        """This method closes the database correctly."""
        
        if self.filepath is not None:
            if path.isfile(self.filepath+'.lock'):
                remove(self.filepath+'.lock')
            self.filepath = None
            self.read_only = False
            self.lock()
            return True
        else:
            raise KPError('Can\'t close a not opened file')
            return False

    def lock(self):
        """This method locks the database."""
        
        self.password = None
        self.keyfile = None
        self.groups[:] = []
        self._entries[:] = []
        self._group_order[:] = []
        self._entry_order[:] = []
        self._root_group = StdGroup()
        self._unsupported_g_fields[:] = []
        self._unsupported_e_fields[:] = []
        self._num_entries = 1
        self._num_entries = 0
        return True

    def unlock(self, password = None, keyfile = None):
        """Unlock the database.
        
        masterkey is needed.

        """

        if ((password is None or password == "") and (keyfile is None or
             keyfile == "")):
            raise KPError("A password/keyfile is needed")
            return False
        elif ((type(password) is not str and password is not None) or
              (type(keyfile) is not str and keyfile is not None)):
            raise KPError("password/keyfile must be a string.")
            return False
        if keyfile == "": keyfile = None;
        if password == "": password = None;
        self.password = password
        self.keyfile = keyfile
        return self.load() 

    def create_group(self, title = None, parent = None, image = 1,
                     y = 2999, mon = 12, d = 28, h = 23, min_ = 59,
                     s = 59):
        """This method creates a new group.

        A group title is needed or no group will be created.

        If a parent is given, the group will be created as a sub-group.

        title must be a string, image an unsigned int >0 and parent a StdGroup.

        With y, mon, d, h, min_ and s you can set an expiration date like on
        entries.

        """
        
        if title is None:
            raise KPError("Need a group title to create a group.")
            return False
        elif type(title) is not str or image < 1 or(parent is not None and \
            type(parent) is not StdGroup) or type(image) is not int:
            raise KPError("Wrong type or value for title or image or parent")
            return False

        id_ = 1
        for i in self.groups:
            if i.id_ >= id_:
                id_ = i.id_ + 1
        group = StdGroup(id_, title, image, self)
        group.creation = datetime.now().replace(microsecond=0)
        group.last_mod = datetime.now().replace(microsecond=0)
        group.last_access = datetime.now().replace(microsecond=0)
        if group.set_expire(y,mon,d,h,min_,s) is False:
            group.set_expire()
        
        # If no parent is given, just append the new group at the end
        if parent is None:
            group.parent = self._root_group
            self._root_group.children.append(group)
            group.level = 0
            self.groups.append(group)
        # Else insert the group behind the parent
        else:
            if parent in self.groups:
                parent.children.append(group)
                group.parent = parent
                group.level = parent.level+1
                self.groups.insert(self.groups.index(parent)+1, group)
            else:
                raise KPError("Given parent doesn't exist")
                return False
        self._num_groups += 1
        return True

    def remove_group(self, group = None):
        """This method removes a group.

        The group needed to remove the group.

        group must be a StdGroup.
        
        """

        if group is None:
            raise KPError("Need group to remove a group")
            return False
        elif type(group) is not StdGroup:
            raise KPError("group must be StdGroup")
            return False

        children = []
        entries = []
        if group in self.groups:
            # Save all children and entries to
            # delete them later
            children.extend(group.children)
            entries.extend(group.entries)
            # Finally remove group
            group.parent.children.remove(group)
            self.groups.remove(group)
        else:
            raise KPError("Given group doesn't exist")
            return False
        self._num_groups -= 1
        
        for i in children:
            self.remove_group(i)
        for i in entries:
            self.remove_entry(i)     
        return True

    def move_group(self, group = None, parent = None):
        """Append group to a new parent.

        group and parent must be StdGroup-instances.

        """

        if group is None or type(group) is not StdGroup:
            raise KPError("A valid group must be given.")
            return False
        elif parent is not None and type(parent) is not StdGroup:
            raise KPError("parent must be a StdGroup.")
            return False
        elif group is parent:
            raise KPError("group and parent must not be the same group")
            return False
        if parent is None: parent = self._root_group;
        if group in self.groups:
            self.groups.remove(group)
            group.parent.children.remove(group)
            group.parent = parent
            if parent.children:
                if parent.children[-1] is self.groups[-1]:
                    self.groups.append(group)
                else:
                    new_index = self.groups.index(parent.children[-1]) + 1
                    self.groups.insert(new_index, group)
            else:
                new_index = self.groups.index(parent) + 1
                self.groups.insert(new_index, group)
            parent.children.append(group)
            if parent is self._root_group:
                group.level = 0
            else:
                group.level = parent.level + 1
            if group.children: self._move_group_helper(group);
            group.last_mod = datetime.now().replace(microsecond=0)
            return True
        else:
            raise KPError("Didn't find given group.")
            return False

    def move_group_in_parent(self, group = None, index = None):
        """Move group to another position in group's parent.
        
        index must be a valid index of group.parent.groups

        """
        
        if group is None or index is None:
            raise KPError("group and index must be set")
            return False
        elif type(group) is not StdGroup or type(index) is not int:
            raise KPError("group must be a StdGroup-instance and index "
                          "must be an integer.")
            return False
        elif group not in self.groups:
            raise KPError("Given group doesn't exist")
            return False
        elif index < 0 or index >= len(group.parent.children):
            raise KPError("index must be a valid index if group.parent.groups")
            return False
        else:
            group_at_index = group.parent.children[index]
            pos_in_parent = group.parent.children.index(group) 
            pos_in_groups = self.groups.index(group)
            pos_in_groups2 = self.groups.index(group_at_index)

            group.parent.children[index] = group
            group.parent.children[pos_in_parent] = group_at_index
            self.groups[pos_in_groups2] = group
            self.groups[pos_in_groups] = group_at_index
            if group.children: self._move_group_helper(group);
            if group_at_index.children: self._move_group_helper(group_at_index);
            group.last_mod = datetime.now().replace(microsecond=0)
            return True

    def _move_group_helper(self, group):
        """A helper to move the chidren of a group."""

        for i in group.children:
            self.groups.remove(i)
            i.level = group.level + 1
            self.groups.insert(self.groups.index(group) + 1, i)
            if i.children: self._move_group_helper(i);

    def create_entry(self, group = None, title = "", image = 1, url = "",
                     username = "", password = "", comment = "",
                     y = 2999, mon = 12, d = 28, h = 23, min_ = 59,
                     s = 59):
        """This method creates a new entry.
        
        The group which should hold the entry is needed.

        image must be an unsigned int >0, group a StdGroup.
        
        It is possible to give an expire date in the following way:
            - y is the year between 1 and 9999 inclusive
            - mon is the month between 1 and 12
            - d is a day in the given month
            - h is a hour between 0 and 23
            - min_ is a minute between 0 and 59
            - s is a second between 0 and 59

        The special date 2999-12-28 23:59:59 means that entry expires never.
        
        """
        
        if type(title) is not str or type(image) is not int or image < 0 or \
            type(url) is not str or type(username) is not str or \
            type(password) is not str or type(comment) is not str or \
            type(y) is not int or type(mon) is not int or type(d) is not int or \
            type(h) is not int or type(min_) is not int or type(s) is not int or\
            type(group) is not StdGroup:
            raise KPError("One argument has not a valid type.")
            return False
        elif group not in self.groups:
            raise KPError("Group doesn't exist.")
            return False
        elif y > 9999 or y < 1 or mon > 12 or mon < 1 or d > 31 or d < 1 or \
            h > 23 or h < 0 or min_ > 59 or min_ < 0 or s > 59 or s < 0:
            raise KPError("No legal date")
            return False
        elif ((mon == 1 or mon == 3 or mon == 5 or mon == 7 or mon == 8 or \
             mon == 10 or mon == 12) and d > 31) or ((mon == 4 or mon == 6 or \
             mon == 9 or mon == 11) and d > 30) or (mon == 2 and d > 28):
            raise KPError("Given day doesn't exist in given month")
            return False
        
        uuid = Random.get_random_bytes(16)
        entry = StdEntry(group.id_, group, image, title, url, username,
                         password, comment, 
                         datetime.now().replace(microsecond = 0),
                         datetime.now().replace(microsecond = 0),
                         datetime.now().replace(microsecond = 0),
                         datetime(y, mon, d, h, min_, s),
                         uuid)
        self._entries.append(entry)
        group.entries.append(entry)
        self._num_entries += 1
        return True

    def remove_entry(self, entry = None):
        """This method can remove entries.
        
        The StdEntry-object entry is needed.
        
        """
        
        if entry is None or type(entry) is not StdEntry:
            raise KPError("Need an entry.")
            return False
        elif entry in self._entries:
            entry.group.entries.remove(entry)
            self._entries.remove(entry)
            self._num_entries -= 1
            return True
        else:
            raise KPError("Given entry doesn't exist.")
            return False

    def move_entry(self, entry = None, group = None):
        """Move an entry to another group.

        A StdGroup group and a StdEntry entry are needed.

        """

        if entry is None or group is None or type(entry) is not StdEntry or \
            type(group) is not StdGroup:
            raise KPError("Need an entry and a group.")
            return False
        elif entry not in self._entries:
            raise KPError("No entry found.")
            return False
        elif group in self.groups:
            entry.group.entries.remove(entry)
            group.entries.append(entry)
            entry.group_id = group.id_
            return True
        else:
            raise KPError("No group found.")
            return False
                
    def move_entry_in_group(self, entry = None, index = None):
        """Move entry to another position inside a group.

        An entry and a valid index to insert the entry in the
        entry list of the holding group is needed. 0 means
        that the entry is moved to the first position 1 to
        the second and so on.

        """

        if entry is None or index is None or type(entry) is not StdEntry \
            or type(index) is not int:
            raise KPError("Need an entry and an index.")
            return False
        elif index < 0 or index > len(entry.group.entries)-1:
            raise KPError("Index is not valid.")
            return False
        elif entry not in self._entries:
            raise KPError("Entry not found.")
            return False
        
        pos_in_group = entry.group.entries.index(entry)
        pos_in_entries = self._entries.index(entry)
        entry_at_index = entry.group.entries[index]
        pos_in_entries2 = self._entries.index(entry_at_index)

        entry.group.entries[index] = entry
        entry.group.entries[pos_in_group] = entry_at_index
        self._entries[pos_in_entries2] = entry
        self._entries[pos_in_entries] = entry_at_index
        return True

    def _transform_key(self, masterkey):
        """This method creates the key to decrypt the database"""

        aes = AES.new(self._transf_randomseed, AES.MODE_ECB)

        # Encrypt the created hash
        for i in range(self._key_transf_rounds):
            masterkey = aes.encrypt(masterkey)

        # Finally, hash it again...
        sha_obj = SHA256.new()
        sha_obj.update(masterkey)
        masterkey = sha_obj.digest()
        # ...and hash the result together with the randomseed
        sha_obj = SHA256.new()
        sha_obj.update(self._final_randomseed + masterkey)
        return sha_obj.digest()

    def _get_passwordkey(self):
        """This method just hashes self.password."""

        sha = SHA256.new()
        sha.update(self.password.encode('utf-8'))
        return sha.digest()

    def _get_filekey(self):
        """This method creates a key from a keyfile."""

        try:
            handler = open(self.keyfile, 'rb')
            buf = handler.read()
        except:
            raise KPError('Could not open file.')
            return False
        finally:
            handler.close()
        sha = SHA256.new()
        if len(buf) == 33:
            sha.update(buf)
            return sha.digest()
        elif len(buf) == 65:
            sha.update(struct.unpack('<65s', buf)[0].decode())
            return sha.digest()
        else:
            while buf:
                if len(buf) <= 2049:
                    sha.update(buf)
                    buf = []
                else:
                    sha.update(buf[:2048])
                    buf = buf[2048:]
            return sha.digest()

    def _cbc_decrypt(self, final_key, crypted_content):
        """This method decrypts the database"""

        # Just decrypt the content with the created key
        aes = AES.new(final_key, AES.MODE_CBC, self._enc_iv)
        decrypted_content = aes.decrypt(crypted_content)
        padding = decrypted_content[-1]
        decrypted_content = decrypted_content[:len(decrypted_content)-padding]
        
        return decrypted_content

    def _cbc_encrypt(self, content, final_key):
        """This method encrypts the content."""

        aes = AES.new(final_key, AES.MODE_CBC, self._enc_iv)
        padding = (16 - len(content) % AES.block_size)

        for i in range(padding):
            content += chr(padding).encode()

        temp = bytes(content)
        return aes.encrypt(temp)

    def _read_group_field(self, group, levels, field_type, field_size,  
                          decrypted_content):
        """This method handles the different fields of a group"""

        if field_type == 0x0000:
            # Ignored (commentar block)
            pass
        elif field_type == 0x0001:
            group.id_ = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0002:
            try:
                group.title = str(struct.unpack('<{0}s'.format(field_size-1),
                                            decrypted_content[:field_size-1])[0],
                                            'utf-8')
            except UnicodeDecodeError:
                group.title = str(struct.unpack('<{0}s'.format(field_size-1),
                                            decrypted_content[:field_size-1])[0],
                                            'latin-1')
            decrypted_content = decrypted_content[1:]
        elif field_type == 0x0003:
            group.creation = self._get_date(decrypted_content)
        elif field_type == 0x0004:
            group.last_mod = self._get_date(decrypted_content)
        elif field_type == 0x0005:
            group.last_access = self._get_date(decrypted_content)
        elif field_type == 0x0006:
            group.expire = self._get_date(decrypted_content)
        elif field_type == 0x0007:
            group.image = struct.unpack('<I', decrypted_content[:4])[0]
        elif field_type == 0x0008:
            level = struct.unpack('<H', decrypted_content[:2])[0]
            group.level = level
            levels.append(level)
        elif field_type == 0x0009:
            group.flags = struct.unpack('<I', decrypted_content[:4])[0]
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
            entry.uuid = decrypted_content[:16]
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
            entry.creation = self._get_date(decrypted_content)
        elif field_type == 0x000A:
            entry.last_mod = self._get_date(decrypted_content)
        elif field_type == 0x000B:
            entry.last_access = self._get_date(decrypted_content)
        elif field_type == 0x000C:
            entry.expire = self._get_date(decrypted_content)
        elif field_type == 0x000D:
            entry.binary_desc = str(struct.unpack('<{0}s'.format(field_size-1),
                                       decrypted_content[:field_size-1])[0],
                                       'utf-8')
        elif field_type == 0x000E:
            entry.binary = decrypted_content[:field_size]
        elif field_type == 0xFFFF:
            pass
        else:
            return False
        return True

    def _get_date(self, decrypted_content):
        """This method is used to decode the packed dates of entries"""
        
        # Just copied from original KeePassX source
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

    def _pack_date(self, date):
        """This method is used to encode dates"""
        
        # Just copied from original KeePassX source
        y, mon, d, h, min_, s = date.timetuple()[:6]

        dw1 = 0x0000FFFF & ((y>>6) & 0x0000003F)
        dw2 = 0x0000FFFF & ((y & 0x0000003F)<<2 | ((mon>>2) & 0x00000003))
        dw3 = 0x0000FFFF & (((mon & 0x0000003)<<6) | ((d & 0x0000001F)<<1) \
                | ((h>>4) & 0x00000001))
        dw4 = 0x0000FFFF & (((h & 0x0000000F)<<4) | ((min_>>2) & 0x0000000F))
        dw5 = 0x0000FFFF & (((min_ & 0x00000003)<<6) | (s & 0x0000003F))

        return struct.pack('<5B', dw1, dw2, dw3, dw4, dw5)        

    def _create_group_tree(self, levels):
        """This method creates a group tree"""

        if levels[0] != 0:
            raise KPError("Invalid group tree")
            return False
        
        for i in range(len(self.groups)):
            if(levels[i] == 0):
                self.groups[i].parent = self._root_group
                self.groups[i].index = len(self._root_group.children)
                self._root_group.children.append(self.groups[i])
                continue

            j = i-1
            while j >= 0:
                if levels[j] < levels[i]:
                    if levels[i]-levels[j] != 1:
                        raise KPError("Invalid group tree")
                        return False
                    
                    self.groups[i].parent = self.groups[j]
                    self.groups[i].index = len(self.groups[j].children)
                    self.groups[i].parent.children.append(self.groups[i])
                    break
                if j == 0:
                    raise KPError("Invalid group tree")
                    return False
                j -= 1
            
        for e in range(len(self._entries)):
            for g in range(len(self.groups)):
                if self._entries[e].group_id == self.groups[g].id_:
                    self.groups[g].entries.append(self._entries[e])
                    self._entries[e].group = self.groups[g]
                    # from original KeePassX-code, but what does it do?
                    self._entries[e].index = 0           
        return True

    def _save_group_field(self, field_type, group):
        """This method packs a group field"""
        
        if field_type == 0x0000:
            # Ignored (commentar block)
            pass
        elif field_type == 0x0001:
            if group.id_ is not None:
                return (4, struct.pack('<I', group.id_))
        elif field_type == 0x0002:
            if group.title is not None:
                return (len(group.title.encode())+1,
                        (group.title+'\0').encode())
        elif field_type == 0x0003:
            if group.creation is not None:
                return (5, self._pack_date(group.creation))
        elif field_type == 0x0004:
            if group.last_mod is not None:
                return (5, self._pack_date(group.last_mod))
        elif field_type == 0x0005:
            if group.last_access is not None:
                return (5, self._pack_date(group.last_access))
        elif field_type == 0x0006:
            if group.expire is not None:
                return (5, self._pack_date(group.expire))
        elif field_type == 0x0007:
            if group.image is not None:
                return (4, struct.pack('<I', group.image))
        elif field_type == 0x0008:
            if group.level is not None:
                return (2, struct.pack('<H', group.level))
        elif field_type == 0x0009:
            if group.flags is not None:
                return (4, struct.pack('<I', group.flags))
        return False

    def _save_entry_field(self, field_type, entry):
        """This group packs a entry field"""

        if field_type == 0x0000:
            # Ignored
            pass
        elif field_type == 0x0001:
            if entry.uuid is not None:
                return (16, entry.uuid)
        elif field_type == 0x0002:
            if entry.group_id is not None:
                return (4, struct.pack('<I', entry.group_id))
        elif field_type == 0x0003:
            if entry.image is not None:
                return (4, struct.pack('<I', entry.image))
        elif field_type == 0x0004:
            if entry.title is not None:
                return (len(entry.title.encode())+1,
                         (entry.title+'\0').encode())
        elif field_type == 0x0005:
            if entry.url is not None:
                return (len(entry.url.encode())+1, (entry.url+'\0').encode())
        elif field_type == 0x0006:
            if entry.username is not None:
                return (len(entry.username.encode())+1,
                        (entry.username+'\0').encode())
        elif field_type == 0x0007:
            if entry.password is not None:
                return (len(entry.password.encode())+1,
                        (entry.password+'\0').encode())
        elif field_type == 0x0008:
            if entry.comment is not None:
                return (len(entry.comment.encode())+1,
                       (entry.comment+'\0').encode())
        elif field_type == 0x0009:
            if entry.creation is not None:
                return (5, self._pack_date(entry.creation))
        elif field_type == 0x000A:
            if entry.last_mod is not None:
                return (5, self._pack_date(entry.last_mod))
        elif field_type == 0x000B:
            if entry.last_access is not None:
                return (5, self._pack_date(entry.last_access))
        elif field_type == 0x000C:
            if entry.expire is not None:
                return (5, self._pack_date(entry.expire))
        elif field_type == 0x000D:
            if entry.binary_desc is not None:
                return (len(entry.binary_desc.encode())+1,
                        (entry.binary_desc+'\0').encode())
        elif field_type == 0x000E:
            if entry.binary is not None:
                return (len(entry.binary), entry.binary)
        return False

