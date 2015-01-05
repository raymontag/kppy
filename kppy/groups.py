"""implements class v1Group; a simple group of a KeePass 1.x database"""

from datetime import datetime

from kppy.exceptions import KPError

class v1Group(object):
    """v1Group represents a simple group of a KeePass 1.x database.

    Attributes:
    - id_ is the group id (unsigned int)
    - title is the group title (string)
    - image is the image number used in KeePassX (unsigned int)
    - level is needed to create the group tree (unsigned int)
    - parent is the previous group (v1Group)
    - children is a list of all following groups (list of v1Groups)
    - entries is a list of all entries of the group (list of v1Entries)
    - db is the database which holds the group (KPDBv1)
    
    """

    def __init__(self, id_=None, title=None, image=1, db=None,
                 level=0, parent=None, children=None, entries=None,
                 creation=None, last_mod=None, last_access=None,
                 expire=None, flags=None):
        """Initialize a v1Group-instance.

        It's recommended to use create_group of KPDBv1 and not this directly.

        """

        if children is None:
            children = []
        if entries is None:
            entries = []

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
