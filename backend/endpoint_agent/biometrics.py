"""Visible consent management using the enrolled endpoint's existing transport."""
import argparse
from .config import Config
from .protocol import AgentClient
from . import tls


def main():
    parser=argparse.ArgumentParser(description='Manage behavioral biometric consent')
    parser.add_argument('--config',required=True)
    choice=parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--grant',action='store_true'); choice.add_argument('--withdraw',action='store_true')
    args=parser.parse_args(); config=Config(args.config)
    if not config.load(): raise SystemExit('Endpoint configuration could not be loaded')
    server=config.get('server_url'); token=config.get('agent_token'); settings=tls.settings_from_config(config.data)
    if not token: raise SystemExit('Endpoint is not enrolled')
    with AgentClient(server,token,retries=0,allow_insecure_http=settings.get('allow_insecure_http',False),**tls.transport_options(settings,url=server)) as client:
        notice=client.response_request('GET','/api/biometrics/agent/status')
        if not notice['configured']: raise SystemExit('Administrator binding required before capture')
        granted=False
        if args.grant:
            from .education import EducationNotifier
            granted=EducationNotifier._popup({'title':'Behavioral biometric consent','message':notice['purpose'],'education':'OK grants collection consent for 30 days; Cancel declines. Collection also requires the biometrics collector to be explicitly enabled.'})
        client.response_request('POST','/api/biometrics/agent/consent',{'granted':granted})
        print('Biometric consent granted.' if granted else 'Biometric consent withdrawn.')


if __name__=='__main__': main()
