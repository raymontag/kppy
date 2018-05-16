kppy v.1.5.1
============

! Due to a bug in KeePassX it is not possible to decrypt databases encrypted
with a 64Byte-keyfile. Indeed it's possible to open such a database encrypted
by the reference implementation KeePass 1.26 for Windows. !

A Python-module to provide an API to KeePass 1.x files which are also used by
the popular KeePassX.

* License: ISC
* Author: Karsten-Kai König <grayfox@outerhaven.de>
* Stable download: https://github.com/raymontag/kppy/tarball/master
* Website: http://raymontag.github.com/kppy
* Bug tracker: https://github.com/raymontag/kppy/issues?state=open
* Git: git://github.com/raymontag/kppy.git

Features:
---------

* Full Access to KeePass 1.x/KeePassX files:
** Open, save and close KP-files correctly
** Edit KP-files correctly and comfortable
** AES encryption
** First Python module for KeePass 1.x files that supports keyfiles, too.
** First Python-KeePass module for Python 3 (Python 2 is supported, too).

* Some explanation to KeePass databases:
** Database files are encrypted with AES
** Database entries are sorted in groups
** Groups support subgroups
** Every entry has a title for better identification
** Expiration dates for entries

Dependencies:
-------------

* Python 2 or Python 3
* PyCrypto (https://www.dlitz.net/software/pycrypto/)

Install:
--------

Just type "python setup.py install" (or "python3 setup.py install") with root
rights in the root directory of kppy.

WARNING:
--------

As long as the database is opened with this
module, the password is saved as plain text in RAM. Even if
the database was closed correctly it is possible that the password lies
somewhere in your computer's RAM, it's not possible to prevent this in Python.
That is, if your computer is compromised it is possible to dump the password
from memory. To prevent some scenarios you could change the working directory of
Python to /var/empty on UNIX-like systems while using kppy. A core dump wouldn't
 be possible unless you're using kppy as root.

Copyright (c) 2012-2018 Karsten-Kai König <grayfox@outerhaven.de>

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


