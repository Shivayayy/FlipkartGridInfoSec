import smtplib
import ssl
from multiprocessing.managers import Value

import certifi
from django.core.mail.backends.smtp import EmailBackend


class CustomEmailBackend(EmailBackend):
    def open(self):
        if self.connection is None:
            self.connection = self._get_connection()
        return super().open()

    def _get_connection(self):
        username = 'shivaycodechef@gmail.com'
        password = 'zmfeemezfgvzllpr'

        if not username:
            raise ValueError("username not set")
        if not password:
            raise ValueError("password not set")
        if not username or not password:
            raise ValueError("SMTP username or password not set")

        context = ssl.create_default_context(cafile=certifi.where())
        connection = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
        connection.starttls(context=context)
        connection.login(username, password)
        return connection
