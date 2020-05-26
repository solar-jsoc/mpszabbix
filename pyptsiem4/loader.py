import json
from cryptography.fernet import Fernet
import base64
import ssl
import logging
import os


class SIEMConfig:
    def __init__(self, cfg):            
        self.logger = logging.getLogger(__name__)
        if 'DEBUG' in os.environ:
            self.logger.setLevel(logging.DEBUG)
        else:  # TODO get log level from config
            self.logger.setLevel(logging.INFO)
        
        self.__cfgfile = cfg
        try:
            self.__conf = self.loadconf()
        except:
            self.__conf = None
            self.logger.warning("Cannot load config file - is it exists and readable?")


    def loadconf(self):
        with open(self.__cfgfile, 'r', encoding='utf-8') as fp:
            return json.loads(fp.read())

    def __retstr(self, callback=None):
        if callback is not None:
            str2 = callback()
        else:
            str2 = b'\xaf~\x9a+\xcf\xc4rg\xb1\xbai\x90\xa4\xd6\xb8pN\xc9\x8c\xe8\x02h6\x8b/\xc6v\xb9\x98\x17\xb1\x8b'
        return base64.urlsafe_b64encode(str2[:32])

    def __passwd(self, pwd):
        key = self.__retstr()
        f = Fernet(key)
        return base64.urlsafe_b64encode(f.encrypt(pwd.encode("raw_unicode_escape"))).decode('utf-8')

    def __unpasswd(self, pwd):
        key = self.__retstr()
        f = Fernet(key)
        return f.decrypt(base64.urlsafe_b64decode(pwd.encode('utf-8'))).decode('utf-8')

    def saveconf(self):
        with open(self.__cfgfile, 'w+', encoding='utf-8') as fp:
            json.dump(self.__conf, fp, indent=3)
        self.logger.info("Configuration saved successfully!")

    def __find(self, name):
        if name not in self.__conf:
            try:
                name = next((cname for cname in self.__conf if self.__conf is not None and cname in self.__conf and 'server' in self.__conf[cname] and  self.__conf[cname]['server'] == name), None)
            except StopIteration as e:
                self.logger.fatal("No {} found in configuration as parameter name or server address.".format(name))
                raise Exception("No {} found in configuration as parameter name or server address.".format(name))
            except TypeError as e:
                self.logger.fatal("No configuration file loaded or configuration is empty!")
                raise ValueError("No configuration file loaded or configuration is empty!") from e
        return name

    def load_server_from_cfg(self, name):
        name = self.__find(name)
        conf = self.__conf[name]
        conf['password'] = self.__unpasswd(conf['password'])
        return conf

    def update_server(self, name, login=None, password=None, cafile=None, proxy=None):
        assert login is not None or password is not None or cafile is not None or proxy is not None
        name = self.__find(name)
        conf = self.load_server_from_cfg(name)
        if login is not None:
            old_login = conf['login']
            conf['login'] = login
            self.logger.info("Login of server named {0} changed from {1} to {2}".format(name, old_login, login))
        if password is not None and password != '':
            conf['password'] = self.__passwd(password)
            self.logger.info("Password of server named {0} changed".format(name))
        if cafile is not None:
            conf['cafile'] = cafile
            self.logger.info("CAFILE of server named {0} changed to {1}".format(name, cafile))
        if proxy is not None:
            if 'proxy' in conf:
                old_proxy = conf['proxy']
            else:
                old_proxy = 'null'
            conf['proxy'] = proxy
            self.logger.info("Proxy of server named {0} changed from {1} to {2}".format(name, old_proxy, proxy))

        self.__conf.update({name: conf})
        self.saveconf()
        self.logger.info("Configuration updated successfully!")

    def add_new_server(self, host, login, password, cafile=None, siemclass=None, name=None, proxy=None, sessionpersist=None):
        if siemclass is not None:
            dochecks = True
        else:
            dochecks = False
        if name is None:
            name = host

        server = {name: {'core': host, 'login': login, 'password': password}}

        if proxy is not None:
            server[name]['proxy'] = proxy
        if sessionpersist is not None:
            server[name]['cookiejar'] = sessionpersist
        if cafile is not None and cafile != "False" and cafile != "false":
            server[name]['cafile'] = cafile
            self.logger.debug("using cafile: " + cafile)
        elif cafile is not None and (not cafile or cafile == "False" or cafile == "false"):  # cafile is False, check disabled
            cafile = False
            server[name]['cafile'] = False
            self.logger.warning("UNSAFE CONFIGURATION - disabled SSL verification")
        elif 'CAFILE' in os.environ:
            self.logger.debug("using cafile: " + os.environ['CAFILE'])
        elif cafile is None:
            p = os.getcwd()
            cafile = p + "/" + "tls-ca-bundle.pem"
        if cafile:
            try:
                ssl.get_server_certificate((host, 443), ca_certs=cafile)
                self.logger.info("Server's certificate of {0} checked against cafile {1} successfully, no additional actions needed.".format(host, cafile))
            except ssl.CertificateError:
                self.logger.fatal("Certificate of {0} failed check against cafile {1}, add instance's root certificate to cafile! Instruction in README file.".format(host, cafile), exc_info=True)
                return
        if dochecks:
            try:
                siem = siemclass(server[name], sessionPersist=sessionpersist)
                siem.login()
                if siem.server != host:
                    self.logger.error("real core name {0} doesn't match specified name {1}! Name would be replaced in configuration!".format(siem.server, host))
                    server[name]['core'] = siem.server
            except:
                self.logger.fatal("Can't login to {}! Check credentials. Full error traceback follows:".format(host), exc_info=True)
                return
        server[name]['password'] = self.__passwd(server[name]['password'])
        if self.__conf is None:
            self.__conf = {}
        self.__conf.update(server)
        self.saveconf()


    def remove_server(self, name):
        if name in self.__conf:
            del self.__conf[name]
            self.saveconf()
        else:
            raise Exception("{} not found in current configuration".format(name))
