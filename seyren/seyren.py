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
        _check_fields = ['checkId',
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

    def get_alerts(self):
        ''' Get alerts for this check '''
        pass

    def delete_alerts(self, before):
        ''' Delete alerts for this check before the specified date
        :param before: the date before to delete alerts
        :param type: datetime
        :returns: Nothing on success, or throws exception
        :rtype: None
        :raises: SeyrenAlertException
        '''
        pass

    def create(self, check):
        '''
        Parameter	Required	Description	                Type
        name	        true	        Name of the check	        String
        description	false	        Description of the check	String
        target	        true	        Name of the metric in graphite	String
        warn	        true	        Warn level	                String
        error	        true	        Error level	                String
        enabled	        true	        Enable/Disable value	        boolean
        live	        false	        Live value (pickle protocol)	boolean
        from	        false	        Specifies the beginning	        String
        until	        false	        Specifies the end	        String
        '''
        pass

    def update(self):
        pass

    def delete(self):
        pass

    def create_subscription(self):
        pass

    def update_subscription(self):
        pass

    def delete_subscription(self):
        pass

    def test_subscription(self, subscription):
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

    def get_checks(self, **kwargs):
        ''' Get all configured checks
        Optional kwargs:
        state
        enabled
        name
        fields
        regexes
        '''
        pass

    def get_check(self, checkId):
        pass


    def get_chart_for_target(self, target):
        pass

