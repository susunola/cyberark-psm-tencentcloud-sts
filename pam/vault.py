"""PVWA v10-family REST adapter; no login/MFA bypass or automatic write retries."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

import requests


def _has_dot_segment(path: str) -> bool:
    """Detect '.'/'..' segments (including percent-encoded) before the client normalises them.

    No internal caller builds such a route; rejecting them keeps a future caller from
    escaping the API prefix if a value ever reaches a path unencoded.
    """
    return any(
        segment.lower().replace('%2e', '.') in ('.', '..')
        for segment in path.split('?', 1)[0].split('/')
    )


class VaultError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class Vault:
    def __init__(
        self,
        api_url: str,
        token: str,
        ca: bool | str = True,
        session: requests.Session | None = None,
    ) -> None:
        if (
            not isinstance(api_url, str)
            or not api_url
            or len(api_url) > 2048
            or any(ord(c) < 33 for c in api_url)
            or '\\' in api_url
            # An empty query/fragment parses as falsy, but the raw delimiter would
            # survive into self.url and truncate every later route.
            or '?' in api_url
            or '#' in api_url
        ):
            raise ValueError('Use an explicit HTTPS PVWA API base URL')
        try:
            parsed = urlsplit(api_url)
            port = parsed.port
            valid = (
                parsed.scheme == 'https'
                and bool(parsed.hostname)
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and (port is None or 1 <= port <= 65535)
                and parsed.path.rstrip('/').lower().endswith('/passwordvault/api')
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValueError('Use an explicit HTTPS PVWA API base URL')
        ca_ok = ca is True or (isinstance(ca, str) and bool(ca.strip()))
        if not ca_ok or not isinstance(token, str) or not 1 <= len(token) <= 16384 or any(ord(c) < 32 or ord(c) == 127 for c in token):
            raise ValueError('TLS verification and an authorized PVWA session are required')
        self.url = api_url.rstrip('/')
        self.token, self.ca = token, ca
        self.session = session or requests.Session()
        self.session.trust_env = False

    def request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        *,
        accept: str = 'application/json',
    ) -> Any:
        if (
            method not in ('GET', 'POST', 'DELETE')
            or not isinstance(path, str)
            or not path.startswith('/')
            or path.startswith('//')
            or '#' in path
            or '\\' in path
            or any(ord(c) < 33 for c in path)
            or _has_dot_segment(path)
        ):
            raise ValueError('Invalid PVWA request route')
        try:
            response = self.session.request(method, self.url + path, json=payload,
                headers={'Authorization': self.token, 'Content-Type': 'application/json', 'Accept': accept},
                timeout=(5, 20), verify=self.ca, allow_redirects=False)
            if not 200 <= response.status_code < 300:
                raise VaultError('PVWA request denied or failed', response.status_code)
            return response.json() if response.content else None
        except VaultError:
            raise
        except Exception:  # noqa: BLE001 - never forward error text
            # No response body, URL, token, request payload or raw exception is returned.
            raise VaultError('PVWA request failed; verify API capability, TLS and permissions') from None

    @staticmethod
    def account_path(account_id: str) -> str:
        if not isinstance(account_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', account_id):
            raise ValueError('Invalid Vault account ID')
        return '/Accounts/' + quote(account_id, safe='')

    def capability_probe(self) -> dict[str, Any]:
        result = self.request('GET', '/Accounts?limit=1')
        if not isinstance(result, dict) or not isinstance(result.get('value'), list):
            raise VaultError('Unsupported account-list response')
        resources = {'Accounts': 'available-read'}
        for resource in ('LiveSessions', 'Recordings', 'IncomingRequests', 'MyRequests'):
            try:
                value = self.list_operations(resource, limit=1)
                resources[resource] = 'available-read' if isinstance(value, (dict, list)) else 'unexpected-response'
            except VaultError as error:
                resources[resource] = {401: 'authentication-required', 403: 'permission-denied',
                    404: 'unsupported-or-hidden', 405: 'method-unsupported'}.get(error.status if error.status is not None else -1, 'probe-failed')
        return {'account_list': True, 'resources': resources, 'writes': 'not probed',
                'native_cpm': 'requires an installed platform', 'session_recording': 'provided by PSM'}

    def account(self, account_id: str) -> dict[str, Any]:
        result = self.request('GET', self.account_path(account_id))
        if not isinstance(result, dict) or result.get('id') != account_id:
            raise VaultError('Unexpected account response')
        return result

    def secret(self, account_id: str, reason: str) -> str:
        result = self.request('POST', self.account_path(account_id) + '/Password/Retrieve', {'reason': reason})
        if not isinstance(result, str) or not result:
            raise VaultError('Unexpected secret response')
        secret_value: str = result
        return secret_value

    def create(self, payload: dict[str, Any]) -> str:
        result = self.request('POST', '/Accounts', payload)
        if not isinstance(result, dict) or not result.get('id'):
            raise VaultError('Account creation result is uncertain; reconcile before retry')
        account_id: str = result['id']
        return account_id

    def list_operations(self, resource: str, limit: int = 100, offset: int = 0) -> Any:
        if resource not in ('Accounts', 'LiveSessions', 'Recordings', 'IncomingRequests', 'MyRequests'):
            raise ValueError('Unsupported operational resource')
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError('Invalid page bounds')
        # Approval list APIs differ in pagination support. Preserve their native response.
        query = f'?limit={limit}&offset={offset}' if resource in ('Accounts', 'LiveSessions', 'Recordings') else ''
        return self.request('GET', '/' + resource + query)

    def session_action(self, session_id: str, action: str) -> dict[str, str]:
        if action not in ('suspend', 'resume', 'terminate'):
            raise ValueError('Unsupported session action')
        identifier = self.account_path(session_id).rsplit('/', 1)[1]
        self.request('POST', '/LiveSessions/' + identifier + '/' + action)
        return {'session_id': session_id, 'action': action, 'status': 'accepted-by-PVWA'}

    def access_request(
        self,
        account_id: str,
        reason: str,
        component: str,
        *,
        ticket_id: str | None = None,
        ticket_system: str | None = None,
        from_date: int | None = None,
        to_date: int | None = None,
    ) -> Any:
        self.account_path(account_id)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise ValueError('A bounded request reason is required')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', component):
            raise ValueError('Explicit connection component required')
        payload: dict[str, Any] = {'AccountID': account_id, 'Reason': reason, 'UseConnect': True, 'ConnectionComponent': component}
        if bool(ticket_id) != bool(ticket_system):
            raise ValueError('Supply ticket ID and system together')
        if ticket_id and ticket_system:
            if not all(isinstance(v, str) and 1 <= len(v) <= 256 for v in (ticket_id, ticket_system)):
                raise ValueError('Invalid ticket fields')
            payload.update(TicketID=ticket_id, TicketingSystem=ticket_system)
        if from_date is not None or to_date is not None:
            if type(from_date) is not int or type(to_date) is not int or not 0 <= from_date < to_date <= 253402300799:
                raise ValueError('Explicit ordered Unix-second request window required')
            payload.update(FromDate=from_date, ToDate=to_date)
        return self.request('POST', '/MyRequests', payload)

    def request_decision(self, request_id: str, decision: str, reason: str) -> dict[str, str]:
        if decision not in ('confirm', 'reject') or not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise ValueError('Explicit decision and reason required')
        identifier = self.account_path(request_id).rsplit('/', 1)[1]
        self.request('POST', '/IncomingRequests/' + identifier + '/' + decision, {'Reason': reason})
        return {'request_id': request_id, 'decision': decision, 'status': 'accepted-by-PVWA'}

    def native_cpm(self, account_id: str, action: str, safe: str, platform: str) -> dict[str, str]:
        if action not in ('Verify', 'Change', 'Reconcile') or not safe or not platform:
            raise ValueError('Explicit native CPM action and scope required')
        account = self.account(account_id)
        if account.get('safeName') != safe or account.get('platformId') != platform:
            raise ValueError('Account is outside the approved CPM scope')
        if account.get('platformAccountProperties', {}).get('TencentSecretId'):
            raise ValueError('CAM key pairs require staged rotation, not guest password CPM actions')
        payload = {'changeImmediately': True} if action == 'Change' else None
        self.request('POST', self.account_path(account_id) + '/' + action, payload)
        return {'account_id': account_id, 'action': action, 'status': 'submitted-to-CPM',
                'completion': 'Check account secretManagement status; submission is not success'}

    def account_status(self, account_id: str) -> dict[str, Any]:
        account = self.account(account_id)
        management = account.get('secretManagement', {})
        # Deliberately exclude extended status/error text, which is vendor/plugin controlled.
        return {'account_id': account_id, 'safe': account.get('safeName'), 'platform': account.get('platformId'),
                'management': {k: management[k] for k in ('automaticManagementEnabled', 'status', 'lastModifiedTime', 'lastReconciledTime') if k in management}}

    def connect(
        self,
        account_id: str,
        component: str,
        reason: str,
        ticket_id: str | None = None,
        ticket_system: str | None = None,
    ) -> Any:
        self.account_path(account_id)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', component) or not isinstance(reason, str) or not reason.strip() or len(reason) > 1024:
            raise ValueError('Explicit component and bounded reason required')
        payload: dict[str, Any] = {'ConnectionComponent': component, 'reason': reason}
        if bool(ticket_id) != bool(ticket_system):
            raise ValueError('Supply ticket ID and system together')
        if ticket_id and ticket_system:
            if len(ticket_id) > 256 or len(ticket_system) > 256:
                raise ValueError('Ticket fields exceed size bounds')
            payload.update(TicketId=ticket_id, TicketingSystemName=ticket_system)
        result = self.request('POST', self.account_path(account_id) + '/PSMConnect', payload)
        if not isinstance(result, (dict, str)) or not result:
            raise VaultError('Unsupported native PSM response')
        return result

    def find_rotation_accounts(self, operation: str) -> list[dict[str, Any]]:
        if not re.fullmatch(r'[a-f0-9]{32}', operation):
            raise ValueError('Invalid rotation operation')
        name = 'tc-rotation-' + operation
        result = self.request('GET', '/Accounts?search=' + name + '&limit=1000')
        if not isinstance(result, dict) or not isinstance(result.get('value'), list):
            raise VaultError('Unsupported account search response')
        if result.get('count', len(result['value'])) > len(result['value']):
            raise VaultError('Incomplete recovery search; inspect PVWA inventory')
        entries = [entry for entry in result['value'] if isinstance(entry, dict)]
        return [entry for entry in entries if entry.get('name') == name]

    def recording(self, recording_id: str, section: str = 'details') -> Any:
        suffixes = {'details': '', 'activities': '/activities', 'properties': '/properties', 'valid': '/valid', 'play': '/Play'}
        if section not in suffixes:
            raise ValueError('Unsupported recording operation')
        identifier = self.account_path(recording_id).rsplit('/', 1)[1]
        return self.request('GET', '/Recordings/' + identifier + suffixes[section])

    def session_details(self, session_id: str, section: str = 'details') -> Any:
        if section not in ('details', 'activities', 'properties'):
            raise ValueError('Unsupported session detail')
        identifier = self.account_path(session_id).rsplit('/', 1)[1]
        return self.request('GET', '/LiveSessions/' + identifier + ('' if section == 'details' else '/' + section))

    def request_details(self, request_id: str, incoming: bool = False) -> Any:
        identifier = self.account_path(request_id).rsplit('/', 1)[1]
        return self.request('GET', ('/IncomingRequests/' if incoming else '/MyRequests/') + identifier)

    def cancel_request(self, request_id: str) -> dict[str, str]:
        identifier = self.account_path(request_id).rsplit('/', 1)[1]
        self.request('DELETE', '/MyRequests/' + identifier)
        return {'request_id': request_id, 'status': 'request-removal-accepted', 'note': 'Existing cloud sessions are not revoked'}

    def find_accounts_by_name(self, name: str, safe: str) -> list[dict[str, Any]]:
        result = self.request('GET', '/Accounts?search=' + quote(name, safe='') + '&limit=1000')
        if not isinstance(result, dict) or not isinstance(result.get('value'), list):
            raise VaultError('Unsupported account lookup')
        if result.get('nextLink') or result.get('count', len(result['value'])) > len(result['value']):
            raise VaultError('Incomplete account lookup; reconcile before onboarding')
        entries = [entry for entry in result['value'] if isinstance(entry, dict)]
        return [entry for entry in entries if entry.get('name') == name and entry.get('safeName') == safe]
