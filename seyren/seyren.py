__author__ = 'ndenev@gmail.com'

import json
import requests
from urllib import urlencode

VERSION = '0.0.1'


class SeyrenException(Exception):
    pass


class SeyrenAlertException(SeyrenException):
    pass


class SeyrenCheckException(SeyrenException):
    pass


class SeyrenCheck(object):
    def __init__(self):
        _alert_fields = ['checkId',
                         'fromType',
                         'toType',
                         'target',
                         'timestamp',
                         'value',
                         'warn',
                         'error',
                         'targetHash',
                         'id']
        pass

class SeyrenAlert(object):
    _alert_fields = ['checkId',
                     'fromType',
                     'toType',
                     'target',
                     'timestamp',
                     'value',
                     'warn',
                     'error',
                     'targetHash',
                     'id']

    def __init__(self, alert):
        for field in self._alert_fields:
            if field not in alert:
                raise SeyrenAlertException('Missing required field: {}'.format(field))
            setattr(self, field, alert[field])

    def __repr__(self):
        return "SeyrenAlert(id: {}, checkId: {}, target: {}, change: {}->{})".format(self.id, self.checkId, self.target, self.fromType, self.toType)

    def __str__(self):
        return self.__repr__()


class SeyrenClient(object):
    def __init__(self, url="http://localhost:8081", auth=None):
        ''' Instantiate new Seyren API client
        :param url: URL of the Seyren Web UI (without /api)
        :type url: string
        :param auth: Authentication method passed to Requests library
        :param type: (user,pass) tuple or other supported authentication.
        :returns: Seyren API client object
        :rtype: SeyrenClient
        '''

        self._url = url
        self._session = requests.Session()
        self._session.headers = headers = {'User-Agent': 'PySeyrenClient-{}'.format(VERSION)}
        if auth is not None:
            self._session.auth = auth

    def _api_call(self, method, url, params):
        ''' Make a call to the API
        :param method: Requests recognized HTTP method.
        :type method: string
        :param url: URL to call
        :type url: string
        :param params: Parameters to pass with the HTTP request.
        :tyep params: dict
        '''

        req = requests.Request(url=url, method=method.upper(), params=params, headers=self._session.headers)
        preq = self._session.prepare_request(req)
        resp = self._session.send(preq)
        resp.raise_for_status()
        return resp.json()

    def get_alerts(self, start=0, items=20):
        alerts = []
        total = 1
        while len(alerts) < total:
            params = {'start': start, 'items': items}
            alert_data = self._api_call('GET', self._url + '/api/alerts', params=urlencode(params))
            total = alert_data['total']
            items = alert_data['items']
            start = alert_data['start'] + items
            alerts.extend([SeyrenAlert(alert) for alert in alert_data['values']])
        return alerts


