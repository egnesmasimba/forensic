"""Explicit LDAPS authentication and bounded AD user/group synchronization."""
import json
import os
import secrets
import ssl

from fastapi import HTTPException
from app.models import User
from app.iam_models import IdentityPolicy
from app.iam import MODULES


def server():
    from ldap3 import Server, Tls
    host = os.environ.get('ZANAQ_AD_HOST','')
    if not host or '/' in host or ':' in host:
        raise HTTPException(503, 'Configure ZANAQ_AD_HOST as a DNS hostname')
    return Server(host, port=636, use_ssl=True, connect_timeout=10,
                  tls=Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=os.environ.get('ZANAQ_AD_CA') or None))


def authenticate(dn, password):
    from ldap3 import Connection
    if not password: return False
    connection = None
    try:
        connection = Connection(server(), user=dn, password=password, auto_bind=True,
                                auto_referrals=False, receive_timeout=10, raise_exceptions=True)
        return bool(connection.bound)
    except HTTPException:
        raise
    except Exception:
        return False
    finally:
        if connection: connection.unbind()


def directory_entries():
    from ldap3 import Connection
    base = os.environ.get('ZANAQ_AD_BASE_DN','')
    bind = os.environ.get('ZANAQ_AD_BIND_DN','')
    password = os.environ.get('ZANAQ_AD_BIND_PASSWORD','')
    if not base or not bind or not password:
        raise HTTPException(503, 'AD search credentials and base DN are not configured')
    connection = None
    try:
        connection = Connection(server(), user=bind, password=password, auto_bind=True,
                                auto_referrals=False, receive_timeout=10, raise_exceptions=True)
        entries = []
        for row in connection.extend.standard.paged_search(base,
            '(&(objectCategory=person)(objectClass=user))',
            attributes=['sAMAccountName','memberOf','userAccountControl'], paged_size=500, generator=True):
            if row.get('type') == 'searchResRef':
                raise ValueError('Referrals require a narrower search base')
            if row.get('type') != 'searchResEntry': continue
            entries.append(row)
            if len(entries) > 5000: raise ValueError('Directory exceeds synchronization limit')
        if connection.result.get('result') != 0: raise ValueError('Incomplete directory search')
        return entries
    except HTTPException: raise
    except Exception:
        raise HTTPException(503, 'AD synchronization failed; no users were changed')
    finally:
        if connection: connection.unbind()


def sync(db):
    from app.auth import hash_password, clear_sessions
    try:
        mappings = json.loads(os.environ['ZANAQ_AD_GROUP_MAP'])
        if not isinstance(mappings, dict) or not mappings: raise ValueError()
        for group, mapping in mappings.items():
            if not isinstance(group,str) or mapping['role'] not in ('administrator','investigator','viewer'):
                raise ValueError()
            modules = mapping.get('modules', [])
            if not isinstance(modules,list) or set(modules)-MODULES-{'*'}: raise ValueError()
            if mapping['role']=='administrator' and modules != ['*']: raise ValueError()
    except (KeyError,ValueError,TypeError):
        raise HTTPException(503, 'Configure explicit AD group-to-role/module mappings')
    entries = directory_entries()  # Finish the bounded search before any mutations.
    seen, changed = set(), 0
    for entry in entries:
        attrs = entry['attributes']
        username = str(attrs.get('sAMAccountName','')).strip().lower()
        if not username or len(username)>120: continue
        dn = entry['dn']
        groups = attrs.get('memberOf') or []
        if isinstance(groups,str): groups=[groups]
        choices = [mapping for group,mapping in mappings.items() if group.lower() in {g.lower() for g in groups}]
        account = db.query(User).filter_by(username=username).first()
        policy = db.get(IdentityPolicy,account.id) if account else None
        # Never convert a local account or reassociate a changed DN automatically.
        if account and (not policy or policy.directory_dn != dn):
            raise HTTPException(409, f'Directory identity conflicts with existing account: {username}')
        disabled = bool(int(attrs.get('userAccountControl',0)) & 2) or not choices
        if not account and disabled: continue
        if not account:
            account=User(username=username,password_hash=hash_password(secrets.token_urlsafe(32)),role='viewer')
            db.add(account); db.flush()
            policy=IdentityPolicy(user_id=account.id,directory_dn=dn); db.add(policy)
        seen.add(account.id)
        if choices:
            # Highest explicitly assigned role; permissions are the mapped group union.
            account.role=max((m['role'] for m in choices),key=lambda r: ('viewer','investigator','administrator').index(r))
            modules=sorted({module for m in choices for module in m.get('modules',[])})
            policy.modules=json.dumps(['*'] if '*' in modules else modules)
        account.disabled=disabled
        clear_sessions(db,account.id); changed+=1
    for policy in db.query(IdentityPolicy).filter(IdentityPolicy.directory_dn != '').all():
        if policy.user_id not in seen:
            db.get(User,policy.user_id).disabled=True; clear_sessions(db,policy.user_id)
    return {'synchronized':changed,'directory_entries':len(entries),'group_membership':'direct memberOf only'}
