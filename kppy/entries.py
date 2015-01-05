"""implements class v1Entry; a simple entry of a KeePass 1.x database"""

from datetime import datetime

from kppy.exceptions import KPError

class v1Entry(object):
    """v1Entry represents a simple entry of a KeePass 1.x database.
 
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
        elif y > 9999 or y < 1 or mon > 12 or mon < 1 or d > 31 or d < 1 or \
            h > 23 or h < 0 or min_ > 59 or min_ < 0 or s > 59 or s < 0:
            raise KPError("No legal date")
        elif ((mon == 1 or mon == 3 or mon == 5 or mon == 7 or mon == 8 or \
             mon == 10 or mon == 12) and d > 31) or ((mon == 4 or mon == 6 or \
             mon == 9 or mon == 11) and d > 30) or (mon == 2 and d > 28):
            raise KPError("Given day doesn't exist in given month")
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
