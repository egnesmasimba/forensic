"""Visible notices on interactive desktops; no acknowledgement on display failure."""
import logging
import threading
from datetime import datetime, timezone


class EducationNotifier:
    def __init__(self, client, show=None):
        self.client = client
        self.show = show or self._popup
        self.busy = False
        self.lock = threading.Lock()

    @staticmethod
    def _popup(warning):
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk(); root.withdraw()
        try:
            body = warning['message'] + '\n\n' + warning.get('education', '')
            if warning.get('training_url'): body += '\n\nAssigned training: ' + warning['training_url']
            return bool(messagebox.askokcancel(warning['title'], body, parent=root))
        finally: root.destroy()

    def consent_notice(self):
        notice = self.client.response_request('GET', '/api/privacy/agent/notice')
        if not notice.get('enabled') or not notice.get('consent_required'): return
        current = notice.get('consent')
        if current and current.get('purpose') == notice.get('purpose'):
            # Withdrawal stays effective until a user deliberately grants again.
            return
        consent = self.show({'title': 'Visual capture consent', 'message': 'Your organization requests screenshot and recording uploads for: ' + notice.get('purpose', ''), 'education': 'OK grants consent for 30 days. Cancel declines. Consent can be withdrawn using the endpoint consent API.'})
        self.client.response_request('POST', '/api/privacy/agent/consent', {'granted': consent, 'purpose': notice['purpose'], 'expires_days': 30})

    def process(self):
        try:
            self.consent_notice()
            result = self.client.response_request('GET', '/api/education/agent/warnings')
            for warning in result.get('warnings', []):
                accepted = self.show(warning)
                self.client.response_request('POST', f"/api/education/agent/warnings/{warning['id']}/receipt", {'action': 'displayed'})
                if accepted:
                    self.client.response_request('POST', f"/api/education/agent/warnings/{warning['id']}/receipt", {'action': 'acknowledged'})
        except Exception as error:
            logging.warning('Policy notification delivery unavailable: %s', type(error).__name__)
        finally:
            with self.lock: self.busy = False

    def poll(self):
        with self.lock:
            if self.busy: return
            self.busy = True
        threading.Thread(target=self.process, name='policy-notification', daemon=True).start()
