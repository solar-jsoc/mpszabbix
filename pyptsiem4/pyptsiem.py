import os
import sys
import logging
import json
import urllib
import ssl
import time
import xml.etree.ElementTree as ET
try:
    import urllib.request as urllib2
except:
    import urllib2
try:
    import http.cookiejar as cookielib
except:
    import cookielib



if sys.version_info[0] < 3:
    from urlparse import urlparse
    from StringIO import StringIO
else:
    from io import StringIO

__all__ = ["PyPtSiem"]

class LoggerWriter:
    '''
    Usage:
    log = logging.getLogger('something')
    sys.stdout = LoggerWriter(log.debug)
    '''
    def __init__(self, level):
        # self.lvlfunc is really like using log.debug(message)
        self.lvlfunc = level
        self._msg = ''

    def write(self, message):
        # if statement reduces the amount of newlines that are
        # printed to the logger
        try:
            message = str(message, encoding='utf-8', errors="ignore")
        except:
            pass
        try:
            self._msg = self._msg + message
        except:
            pass
        lines = self._msg.split("\n")
        self._msg = ''
        for i in lines:
            try:
                i = str(i, encoding='utf-8', errors="ignore")
            except:
                pass
            if i != "":
                self.lvlfunc(i)

    def flush(self):
        # create a flush method so things can be flushed when the system wants to.
        # really don't know if where can be put just pass instead of code
        if self._msg != '':
            lines = self._msg.split("\n")
            self._msg = ''
            for i in lines:
                self.lvlfunc(i)




class PyPtSiem:
    endpoints = {
        19.1: {
            'core': {
                'login-ui': {
                    'url': '/ui/login',
                    'port': 3334,
                    'parameters': {'authType': None, 'username': None, 'password': None}
                },
                'login-account': {
                    'url': '/account/login',
                    'parameters': {'returnurl': "/#/authorization/landing"},
                    'encode': 'url',
                    'method': 'GET'
                },
                'userinfo': {
                    'url': '/api/account/userinfo'
                },
                'tasks': {
                    'url': '/api/scanning/v3/scanner_tasks',
                    'parameters': {'additionalFilter':'scan', 'mainFilter':'all'},
                    'encode': 'url',
                    'method': 'GET'
                },
                'task-stop': {
                    'url': '/api/scanning/v3/scanner_tasks/{task_id}/stop',
                    'parameters': "",
                    'subst': ['task_id'],
                    'method': 'POST'
                },
                'task-start': {
                    'url': '/api/scanning/v3/scanner_tasks/{task_id}/start',
                    'parameters': "",
                    'subst': ['task_id'],
                    'method': 'POST'
                },
                'raw_post': {
                    'url': '{url}',
                    'parameters': "",
                    'subst': ['url'],
                    'method': 'POST',
                    'encode': 'url'
                },
                'raw_get': {
                    'url': '{url}',
                    'subst': ['url'],
                    'method': 'GET',
                    'encode': 'url'
                }

            }
        },
        21.1: {
            'core': {}
        },
        22: {
            'core': {}
        }
    }
    def __init__(self, server, proxyServer=None, username=None, password=None, sessionPersist=None):
        self.logger = logging.getLogger(__name__)
        if 'DEBUG' in os.environ:
            self.logger.setLevel(logging.DEBUG)
        else:  # TODO get log level from config
            self.logger.setLevel(logging.INFO)
        if 'CAFILE' in os.environ:
            self.logger.debug("using cafile: " + os.environ['CAFILE'])
            ctx = ssl.create_default_context(cafile=os.environ['CAFILE'])
        elif server['cafile'] is not None and server['cafile'] != False:
            if isinstance(server['cafile'], bool):
                raise ValueError("Server's cafile must be False or full path to cafile, while it's actually \"True\"")
            self.logger.debug("using cafile: " + server['cafile'])
            ctx = ssl.create_default_context(cafile=server['cafile'])
            ctx.check_hostname = False
        else:
            p = os.getcwd()
            cafile = p + "/" + "tls-ca-bundle.pem"
            if os.path.isfile(cafile):
                self.logger.debug("using cafile: " + cafile)
                ctx = ssl.create_default_context(cafile=cafile)
            else:
                try:
                    import certifi
                    self.logger.debug("using cafile: " + cafile)
                    self.logger.warning("using cafile False, SSL verify DISABLED! Configuration is INSECURE and highly not recommended in production use!")
                    cafile = certifi.where()
                    ctx = ssl._create_unverified_context(cafile=cafile)
                except:
                    self.logger.error("Failed locating cafile!", exc_info=True)
                    raise

        if 'DEBUG' in os.environ:
            ssl_handler = urllib2.HTTPSHandler(debuglevel=1, context=ctx)
            plain_handler = urllib2.HTTPHandler(debuglevel=1)
        else:
            ssl_handler = urllib2.HTTPSHandler(context=ctx)
            plain_handler = urllib2.HTTPHandler()
        # install urllib opener (proxy addr, username, password, port)
        if sessionPersist is not None:
            self.cookies = cookielib.LWPCookieJar(filename=sessionPersist)
            try:
                self.cookies.load(filename=sessionPersist, ignore_discard=True)
            except:
                self.logger.warning('Failed load cookiefile {0}'.format(sessionPersist), exc_info=True)
        else:
            self.cookies = cookielib.LWPCookieJar()

        cookie_opener = urllib2.HTTPCookieProcessor(self.cookies)
        self.sessionPersist = sessionPersist

        if ('proxy' not in server or server['proxy'] is None) and proxyServer is not None:
            if username and password:
                proxy = urllib2.ProxyHandler(
                    {'http': 'http://' + username + ':' + password + '@' + proxyServer,
                     'https': 'https://' + username + ':' + password + '@' + proxyServer})
            else:
                proxy = urllib2.ProxyHandler(
                    {'http': 'http://' + proxyServer, 'https': 'https://' + proxyServer})

        if 'proxy' in server and server['proxy'] is not None:
            if len(server['proxy'].split('://')) > 1:
                proxy = server['proxy'].split('://')
                proxy = urllib2.ProxyHandler({'http': 'http://' + proxy[1], 'https': 'https://' + proxy[1]})
            else:
                proxy = urllib2.ProxyHandler({'http': 'http://' + server['proxy'], 'https': 'https://' + server['proxy']})

            self.opener = urllib2.build_opener(proxy, cookie_opener, ssl_handler, plain_handler)
        else:
            self.opener = urllib2.build_opener(cookie_opener, ssl_handler, plain_handler)

        self.server = server['core']
        self.instance = server

        self.core_logged_on = False
        self.tasks = None

        if proxyServer:
            self.logger.warning(
                "Using of proxyServer, username and password parameters deprecated. Please use 'proxy' key in server definition instead.")

        versions = list(self.endpoints.keys())
        self.urls = self.endpoints[min(versions)]
        versions.remove(min(versions))
        versions.sort()
        if 'core_version' not in server:
            server['core_version'] = max(versions)
        self.logger.debug('Core version is {0}'.format(server['core_version']))
        for i in versions:
            if i <= server['core_version']:
                for k in self.endpoints[i]['core']:
                    self.urls[k] = self.endpoints[i]['core'][k]
            else:
                break
        self.logger.debug("final core endpoints: " + json.dumps(self.urls))


    '''
    All told, urlopen() is thread-safe if the following conditions are met:
    install_opener() is not called from another thread.
    A non-shared Request object, or string is used as the url parameter.
    https://stackoverflow.com/questions/5825151/are-urllib2-and-httplib-thread-safe
    '''
    def request(self, endpoint_name, headers=None, parameters=None, substitutions={}):
        t = 'core'
        if endpoint_name in self.urls[t]:
            endpoint = self.urls[t][endpoint_name]
        else:
            raise Exception("Endpoint {0} not found in endpoints for server {1}".format(endpoint_name, self.server))
        url = ''
        if 'proto' in endpoint:
            substitutions['proto'] = endpoint['proto']
        else:
            substitutions['proto'] = "https"
        if 'port' in endpoint:
            substitutions['port'] = endpoint['port']

        substitutions['core'] = self.server
        if 'port' in endpoint:
            url = '{proto}://{core}:{port}' + endpoint['url']
        elif 'url' not in substitutions or ('url' in substitutions and not '://' in substitutions['url']):
            url = '{proto}://{core}' + endpoint['url']
        else:
            url = endpoint['url']
        if 'subst' in endpoint:
            for i in endpoint['subst']:
                error = ''
                if i not in substitutions:
                    error += "No {0} in substitutions array, where {0} is required!\n".format(i)
                if error != '':
                    self.logger.fatal(error)
                    raise ValueError(error)

        try:
            url = url.format(**substitutions)
        except:
            self.logger.fatal('Error formatting request url', exc_info=True)
            raise
        self.logger.debug("URL: " + url)
        if 'parameters' in endpoint:
            if parameters is not None and endpoint['parameters'] != "":
                for k, v in endpoint['parameters'].items():
                    if v is not None and k not in parameters:
                        parameters[k] = v
            elif parameters is None:
                parameters = endpoint['parameters']

        # HTTP methods that send data in request body (DELETE can by spec, but don't must)
        if ('method' not in endpoint and 'parameters' in endpoint) or ('method' in endpoint and (endpoint['method'] in ['POST', 'PUT'])):
            method = 'POST' if 'method' not in endpoint else endpoint['method']
            if 'encode' not in endpoint or endpoint['encode'] == 'json':
                parameters = self.jsonToParameter(parameters)
                isjson = True
            elif 'encode' in endpoint and endpoint['encode'] == 'url':
                parameters = self.toBytes(self.urlencode(parameters))
                isjson = False
            if 'url_parameters' in endpoint:
                url += self.urlencode(endpoint['url_parameters'])
            req = urllib2.Request(url, method=method)
        elif 'method' in endpoint:
            if parameters is not None:
                url = url + '?' + self.urlencode(parameters)
                parameters = None
            elif 'url_parameters' in endpoint:
                url = url + '?' + self.urlencode(parameters)
            isjson = False
            if endpoint['method'] == "GET":
                req = urllib2.Request(url)
                method = 'GET'
            else:
                method = endpoint['method']
                req = urllib2.Request(url, method=endpoint['method'])
        else:  # method not defined in endpoint definition and
            req = urllib2.Request(url)
        if headers:
            [req.add_header(k, headers[k]) for k in headers.keys()]
        if headers is None and isjson:
            req.add_header('Content-Type', 'application/json')
        result = None
        tmp = sys.stdout
        sys.stdout = LoggerWriter(self.logger.debug)
        try:
            if parameters is not None :
                result = self.opener.open(req, parameters)
            else:
                result = self.opener.open(req)

        except urllib2.HTTPError as e:
            if (e.code == 401 or e.code == 400)  and endpoint_name not in ['login-ui', 'login-account', 'userinfo', 'raw']:
                if self.check_core_loggedin():
                    self.logger.fatal("Error 401 when tried to access endpoint {0}, url {1}".format(endpoint_name, url))
                    raise
                else:
                    try:
                        self.login()
                        if parameters is not None :
                            result = self.opener.open(req, parameters)
                        else:
                            result = self.opener.open(req)

                    except:
                        self.logger.fatal("Login failure", exc_info=True)
                        raise
            elif e.code == 401:
                if endpoint_name != "raw":
                    self.logger.fatal("Login failure, step {0}".format(endpoint_name))
                else:
                    self.logger.fatal("RAW request failure, url {0}".format(url))
                raise
            else:
                if parameters is not None and endpoint_name != 'login-ui':
                    self.logger.fatal("Failed to execute request. Endpoint {0}, url {1}, data {2}".format(endpoint_name, url, parameters))
                else:
                    self.logger.fatal("Failed to execute request. Endpoint {0}, url {1}".format(endpoint_name, url))
                raise
        if self.sessionPersist:
            self.cookies.save(ignore_discard=True)
        sys.stdout = tmp
        return result

    def urlparse(self, result):
        try:
            url = urllib.parse.urlparse(result.geturl())
        except:
            url = urlparse(result.geturl())
        return url

    def jsonToParameter(self, parameters):
        if bytes is str:
            return json.dumps(parameters)
        else:
            return bytes(json.dumps(parameters), encoding="utf-8")

    def toBytes(self, strParameter):
        if bytes is str:
            return strParameter
        else:
            return bytes(strParameter, encoding="utf-8")

    def urlencode(self, parameters):
        try:
            return urllib.parse.urlencode(parameters)
        except:
            return urllib.urlencode(parameters)

    def check_core_loggedin(self):
        try:  # check if we already logged in
            self.request('userinfo')
            self.core_logged_on = True
            return True
        except:
            self.core_logged_on = False
            return False

    def login(self):
        body = None
        if '@' in self.instance['login']:
            self.instance['authtype'] = 1
        parameters = {'authType': self.instance['authtype'] if 'authtype' in self.instance else '0', 'username': self.instance['login'],
                      'password': self.instance['password']}
        if 'newPassword' in self.instance:
            parameters['newPassword'] = self.instance['newPassword']

        result = self.request('login-ui', parameters=parameters)
        result = self.request('login-account')
        if result is not None:
            url = self.urlparse(result)

            if url.hostname != self.server.lower():
                self.logger.warning("Real core address " + url.hostname + " doesn't match address defined in config: " + self.server + "!!! Replacing...")
                self.server = url.hostname
                self.instance['core'] = self.server
                result = self.request('login-ui', parameters=parameters)
                result = self.request('login-account')
                url = self.urlparse(result)

        if "/core/wsfed" in url.path:
            if self.sessionPersist:
                self.cookies.save(ignore_discard=True)
            self.core_logged_on = True

            return

        body = str(result.read().decode("utf-8"))

        if body:
            if not '<html>' in body:
                body = '<html><body>' + body + '</body></html>'
            body = StringIO(body)

            t = ET.ElementTree()

            t.parse(body)

            url = t.find('./body/form').get('action')

            parameters = {}
            for i in t.iterfind('./body/form/input'):
                parameters[i.get('name')] = i.get('value')

            result = self.request('raw_post', parameters=parameters, substitutions={'url': url})

            try:
                t.parse(result)
            except:
                try:
                    body = str(result.read().decode("utf-8"))
                    t.parse(StringIO(body))
                except:
                    raise Exception(body)
            url = t.find('./body/form').get('action')
            parameters = {}
            for i in t.iterfind('./body/form/input'):
                parameters[i.get('name')] = i.get('value')
            
            result = self.request('raw_post', parameters=parameters, substitutions={'url': url})
            
        self.core_logged_on = True

    def getTasksStatus(self):
        if self.tasks is None:
            result = json.load(self.request('tasks'))
            self.tasks = result
        else:
            result = self.tasks
        result = [r for r in result
                  if 'triggerParameters' not in r or
                  ('triggerParameters' in r and ('isEnabled' in r['triggerParameters'] and not r['triggerParameters']['isEnabled']))
                 ]

        return result

    def getTaskIdByName(self, taskName):
        if self.tasks is None:
            result = json.load(self.request('tasks'))
            self.tasks = result
        else:
            result = self.tasks
        for i in result:
            if i['name'] == taskName:
                return i['id']

    def stopTask(self, taskId):
        self.request('task-stop', substitutions={'task_id': taskId})

    def startTask(self, taskId):
        self.request('task-start', substitutions={'task_id': taskId})

    def restartTask(self, taskId=None, taskName=None):
        if not taskId:
            assert taskName != None
            taskId = self.getTaskIdByName(taskName)

        try:
            self.stopTask(taskId)
        except:
            pass
        time.sleep(1)
        self.startTask(taskId)
