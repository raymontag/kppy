from distutils.core import setup

setup( 
     name = "kppy", 
     version = "1.4.0", 
     author = "Karsten-Kai König", 
     author_email = "kkoenig@posteo.de",
     url = "http://raymontag.github.com/kppy",
     download_url = "https://github.com/raymontag/kppy/tarball/master",
     description = "A Python-module to provide an API to KeePass 1.x files which are also used by the popular KeePassX.",
     long_description = ("kppy is a Python-module that provides full access to "
                        "KeePass 1.x password databases which are used by the "
                        "popular password manager KeePassX. Full access means:\n"
                        "\t- Open, save and close KP-files correctly\n"
                        "\t- Edit KP-files correctly and comfortable\n"
                        "\t- AES encryption\n"
                        "\t- First Python module for KeePass 1.x files that supports keyfiles, too.\n"
                        "\t- First Python-KeePass module for Python 3.\n"
                        "Some explanation to KeePass databases: \n"
                        "\t- Database files are encrypted with AES\n"
                        "\t- Database entries are sorted in groups\n"
                        "\t- Groups support subgroups\n"
                        "\t- Every entry has a title for better identification\n"
                        "\t- Expiration dates for entries\n"),
     packages = ['kppy'],
     data_files = [('share/doc/kppy', ['README', 'COPYING'])],
     license = "GPL v3 or later"
     )
