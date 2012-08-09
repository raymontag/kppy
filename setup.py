from distutils.core import setup

setup( 
     name = "kppy", 
     version = "1.1", 
     author = "Karsten-Kai König", 
     author_email = "kkoenig@posteo.de",
     url = "http://www.nongnu.org/kppy/",
     download_url = "http://download.savannah.gnu.org/releases/kppy/",
     description = "A Python-module to provide an API to KeePass 1.x files which are also used by the popular KeePassX.",
     long_description = ("kppy is a Python-module that provides full access to "
                        "KeePass 1.x password databases which are used by the "
                        "popular password manager KeePassX. Full access means:\n"
                        "\t- Open, save and close correctly\n"
                        "\t- Complete and comfortable editing\n"
                        "Other features:\n"
                        "\t- An included secure password generator (planned)\n"
                        "\t- Security features according to the KeePass 1.x "
                        "standard like Twofish encryption (planned)"),
     package_dir = {'' : 'kppy'},
     py_modules = ["kppy"],
     license = "GPL v3 or later"
     )
