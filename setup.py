from distutils.core import setup

setup( 
     name = "kppy", 
     version = "1.5.1",
     author = "Karsten-Kai Koenig", 
     author_email = "grayfox@outerhaven.de",
     url = "http://raymontag.github.com/kppy",
     download_url = "https://github.com/raymontag/kppy/archive/master.zip",
     description = "A Python-module to provide an API to KeePass 1.x files which are also used by the popular KeePassX.",
     long_description = ("kppy is a Python-module that provides full access to "
                        "KeePass 1.x password databases which are used by the "
                        "popular password manager KeePassX. Full access means:\n"
                        "\t- Open, save and close KP-files correctly\n"
                        "\t- Edit KP-files correctly and comfortable\n"
                        "\t- AES encryption\n"
                        "\t- First Python module for KeePass 1.x files that supports keyfiles, too.\n"
                        "\t- First Python-KeePass module for Python 3. (Python 2 is supported, too)\n"
                        "Some explanation to KeePass databases: \n"
                        "\t- Database files are encrypted with AES\n"
                        "\t- Database entries are sorted in groups\n"
                        "\t- Groups support subgroups\n"
                        "\t- Every entry has a title for better identification\n"
                        "\t- Expiration dates for entries\n"),
     packages = ['kppy'],
     install_requires = ['PyCryptodome'],
     data_files = [('share/doc/kppy', ['LICENSE.md', 'README.md'])],
     license = "ISC"
     )
