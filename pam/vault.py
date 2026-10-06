import re
from urllib.parse import urlsplit, quote
import requests


class VaultError(Exception):
    pass


class Vault:
    """PVWA v10-family REST adapter; no login/MFA bypass or automatic write retries."""
    def __init__(self, api_url, token, ca=True, session=None):
        parsed = urlsplit(api_url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Use an explicit HTTPS PVWA API base URL')
        if ca is False or not token:
            raise ValueError('TLS verification and an authorized PVWA session are required')
        self.url = api_url.rstrip('/')
        self.token, self.ca = token, ca
        self.session = session or requests.Session()
        self.session.trust_env = False

    def request(self, method, path, payload=None):
        try:
            response = self.session.request(method, self.url + path, json=payload,
                headers={'Authorization': self.token, 'Content-Type': 'application/json'},
                timeout=(5, 20), verify=self.ca, allow_redirects=False)
            if not 200 <= response.status_code < 300:
                raise VaultError('PVWA request denied or failed')
            return response.json() if response.content else None
        except Exception:
            # No response body, URL, token, request payload or raw exception is returned.
            raise VaultError('PVWA request failed; verify API capability, TLS and permissions') from None

    @staticmethod
    def account_path(account_id):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', account_id):
            raise ValueError('Invalid Vault account ID')
        return '/Accounts/' + quote(account_id, safe='')

    def capability_probe(self):
        result = self.request('GET', '/Accounts?limit=1')
        if not isinstance(result, dict) or not isinstance(result.get('value'), list):
            raise VaultError('Unsupported account-list response')
        return {'account_list': True, 'writes': 'not probed', 'session_recording': 'provided by PSM'}

    def account(self, account_id):
        result = self.request('GET', self.account_path(account_id))
        if not isinstance(result, dict) or result.get('id') != account_id:
            raise VaultError('Unexpected account response')
        return result

    def secret(self, account_id, reason):
        result = self.request('POST', self.account_path(account_id) + '/Password/Retrieve', {'reason': reason})
        if not isinstance(result, str) or not result:
            raise VaultError('Unexpected secret response')
        return result

    def create(self, payload):
        result = self.request('POST', '/Accounts', payload)
        if not isinstance(result, dict) or not result.get('id'):
            raise VaultError('Account creation result is uncertain; reconcile before retry')
        return result['id']

    def list_operations(self, resource, limit=100, offset=0):
        if resource not in ('LiveSessions', 'Recordings', 'IncomingRequests', 'MyRequests'):
            raise ValueError('Unsupported operational resource')
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError('Invalid page bounds')
        # Approval list APIs differ in pagination support. Preserve their native response.
        query = f'?limit={limit}&offset={offset}' if resource in ('LiveSessions', 'Recordings') else ''
        return self.request('GET', '/' + resource + query)

    def session_action(self, session_id, action):
        if action not in ('suspend', 'resume', 'terminate'):
            raise ValueError('Unsupported session action')
        identifier = self.account_path(session_id).rsplit('/', 1)[1]
        self.request('POST', '/LiveSessions/' + identifier + '/' + action)
        return {'session_id': session_id, 'action': action, 'status': 'accepted-by-PVWA'}

    def access_request(self, account_id, reason, component):
        self.account_path(account_id)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise ValueError('A bounded request reason is required')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', component):
            raise ValueError('Explicit connection component required')
        return self.request('POST', '/MyRequests', {'AccountID': account_id, 'Reason': reason,
                            'UseConnect': True, 'ConnectionComponent': component})

    def request_decision(self, request_id, decision, reason):
        if decision not in ('confirm', 'reject') or not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise ValueError('Explicit decision and reason required')
        identifier = self.account_path(request_id).rsplit('/', 1)[1]
        self.request('POST', '/IncomingRequests/' + identifier + '/' + decision, {'Reason': reason})
        return {'request_id': request_id, 'decision': decision, 'status': 'accepted-by-PVWA'}
