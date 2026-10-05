"""Local, deliberate consent withdrawal/renewal using the enrolled endpoint config."""
import argparse
from .config import Config
from .protocol import AgentClient
from . import tls


def main():
    parser = argparse.ArgumentParser(description='Manage endpoint visual capture consent')
    parser.add_argument('--config', required=True)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument('--withdraw', action='store_true')
    options.add_argument('--grant', action='store_true')
    args = parser.parse_args()
    cfg = Config(args.config)
    if not cfg.load(): raise SystemExit('Endpoint configuration could not be loaded')
    server = cfg.get('server_url'); token = cfg.get('agent_token')
    if not token: raise SystemExit('Endpoint is not enrolled')
    settings = tls.settings_from_config(cfg.data)
    with AgentClient(server, token, retries=0, allow_insecure_http=settings.get('allow_insecure_http', False), **tls.transport_options(settings, url=server)) as client:
        notice = client.response_request('GET', '/api/privacy/agent/notice')
        if args.grant:
            from .education import EducationNotifier
            accepted = EducationNotifier._popup({'title':'Visual capture consent', 'message':notice['purpose'], 'education':'OK grants consent for 30 days; Cancel declines.'})
        else: accepted = False
        client.response_request('POST', '/api/privacy/agent/consent', {'granted':accepted, 'purpose':notice['purpose'], 'expires_days':30})
        print('Consent granted for 30 days.' if accepted else 'Consent withdrawn.')


if __name__ == '__main__': main()
