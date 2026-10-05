"""Linux pam_exec adapter. Receives a short-lived IAM ticket on stdin.

The explicit config file must be root-owned, mode 0600, and contain server,
resource, and service_key. No password or ticket is logged or passed in argv.
"""
import argparse
import json
import os
import stat
import ssl
import sys
from urllib.parse import urlsplit
import httpx


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',required=True)
    args=parser.parse_args()
    if os.name != 'posix' or os.environ.get('PAM_TYPE') != 'auth': return 1
    try:
        descriptor=os.open(args.config,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(descriptor) as handle:
            info=os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077: return 1
            config=json.load(handle)
        url=urlsplit(config['server'])
        if url.scheme!='https' or not url.hostname or url.username or url.password or url.path not in ('','/') or url.query or url.fragment: return 1
        ticket=sys.stdin.buffer.read(128).rstrip(b'\0\r\n').decode('ascii')
        username=os.environ.get('PAM_USER','')
        if not username or not ticket: return 1
        # Explicit root-controlled CA bundle supports private enterprise TLS.
        verify = ssl.create_default_context(cafile=config.get('ca_bundle'))
        with httpx.Client(timeout=10,follow_redirects=False,trust_env=False,verify=verify) as client:
            response=client.post(config['server'].rstrip('/')+'/api/iam/pam/redeem',
                headers={'X-PAM-Key':config['service_key']},
                json={'username':username,'resource':config['resource'],'ticket':ticket})
        return 0 if response.status_code==200 and response.json().get('authorized') is True else 1
    except Exception:
        return 1


if __name__=='__main__':
    raise SystemExit(main())
