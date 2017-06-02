__author__ = 'ndenev@gmail.com'

import json
import requests
import cerberus
from abc import ABCMeta, abstractmethod
from urllib import urlencode
from functools import partial

VERSION = '0.0.1'


class SeyrenException(Exception):
    pass


class SeyrenAlertException(SeyrenException):
    pass


class SeyrenCheckException(SeyrenException):
    pass


class SeyrenDataValidationError(SeyrenException):
    pass


class SeyrenBaseObject:
    ''' Default Seyren object class '''
    __metaclass__ = ABCMeta
    _validator = cerberus.Validator()
    _validation_schema = {}

    def __init__(self, params):
        self._data = {}
        self._gen_props(params)

    def _setter(self, key, value):
        if self._validator({key: value}, {key: self._validation_schema[key]}):
            self._data[key] = value
        else:
            _msg = "Failed to validate value: {}".format(self._validator.errors)
            raise SeyrenDataValidationError(_msg)

    def _getter(self, key):
        return self._data.get(key, None)

    def _deleter(self, key):
        self._data[key] = None

    def _add_prop(self, key, value):
        getx = lambda self: self._getter(key)
        setx = lambda self, value: self._setter(key, value)
        delx = lambda self: self._deleter(key)
        setattr(self.__class__, key, property(getx, setx, delx))

    def _gen_props(self, params):
        if not self._validator(params, self._validation_schema):
            raise SeyrenDataValidationError("Failed to validate data: {}".format(self._validator.errors))
        for k, v in map(lambda k: (k, params.get(k, None)), self._validation_schema.keys()):
            self._data[k] = v
            self._add_prop(k, v)

    def __repr__(self):
        return "<{}: {}>".format(self.__class__, hash(frozenset(self._data.items())))

    def __str__(self):
        return "{}".format({k: self._data[k] for k in self._validation_schema.keys()})


class SeyrenSubscription(SeyrenBaseObject):
    _validation_schema = {'target': {'type': 'string'},
                          'type': {'type': 'string'},
                          'ignoreWarn': {'type': 'boolean'},
                          'ignoreError': {'type': 'boolean'},
                          'ignoreOk': {'type': 'boolean'},
                          'notifyOnWarn': {'type': 'boolean'},
                          'notifyOnError': {'type': 'boolean'},
                          'notifyOnOk': {'type': 'boolean'},
                          'fromTime': {'type': 'string', 'regex': '(2[0-4]|[0-1][0-9])[0-5][0-9]'},
                          'toTime': {'type': 'string', 'regex': '(2[0-4]|[0-1][0-9])[0-5][0-9]'},
                          'su': {'type': 'boolean'},
                          'mo': {'type': 'boolean'},
                          'tu': {'type': 'boolean'},
                          'we': {'type': 'boolean'},
                          'th': {'type': 'boolean'},
                          'fr': {'type': 'boolean'},
                          'sa': {'type': 'boolean'},
                          'enabled': {'type': 'boolean'},
                          'id': {'type': 'string', 'regex': '[0-9a-f]+' }}
    def __init__(self, params):
        super(SeyrenSubscription, self).__init__(params)

class SeyrenCheck(SeyrenBaseObject):
    _validation_schema = {'checkId': {'type': 'string', 'regex': '[0-9a-f]+' },
                          'fromType': {'type': 'string' },
                          'toType': {'type': 'string' },
                          'target': {'type': 'string' },
                          'timestamp': {'type': 'integer' },
                          'value': {'type': 'number' },
                          'warn': {'type': 'string' },
                          'error': {'type': 'string' },
                          'targetHash': {'type': 'string' },
                          'id': {'type': 'string', 'regex': '[0-9a-f]+' },
                          'from': {'type': 'string', 'nullable': True},
                          'until': {'type': 'string', 'nullable': True},
                          'description': {'type': 'string', 'nullable': True},
                          'enabled': {'type': 'boolean'},
                          'live': {'type': 'boolean'},
                          'lastCheck': {'type': 'integer', 'nullable': True},
                          'state': {'type': 'string'},
                          'name': {'type': 'string'},
                          'allowNoData': {'type': 'boolean'}}
    _create_fields = ['name', 'description', 'target', 'warn', 'error', 'enabled',
                      'live', 'from', 'until']

    def __init__(self, params, subscriptions = []):
        super(SeyrenCheck, self).__init__(params)
        self.subscriptions = subscriptions

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

    def post_data(self):
        ''' Create body dict for creating checks '''
        _data = {}
        for _key in self._create_fields:
            _attr = getattr(self, _key, None)
            if _attr is None:
                continue
            if isinstance(_attr, bool):
                _attr = str(_attr).lower()
            _data[_key] = str(_attr)
        print 'Data to send:', _data
        return _data

    def create_subscription(self, subscription):
        pass

    def update_subscription(self):
        pass

    def delete_subscription(self):
        pass

    def test_subscription(self, subscription):
        pass

class SeyrenAlert(SeyrenBaseObject):
    '''
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
     '''
    _validation_schema = {'checkId': {'type': 'string', 'regex': '[0-9a-f]+' },
                          'fromType': {'type': 'string' },
                          'toType': {'type': 'string' },
                          'target': {'type': 'string' },
                          'timestamp': {'type': 'integer' },
                          'value': {'type': 'number' },
                          'warn': {'type': 'number' },
                          'error': {'type': 'number' },
                          'targetHash': {'type': 'string' },
                          'id': {'type': 'string', 'regex': '[0-9a-f]+' },
                          'from': {'type': 'string', 'nullable': True},
                          'until': {'type': 'string', 'nullable': True},
                          'description': {'type': 'string', 'nullable': True},
                          'enabled': {'type': 'boolean'},
                          'live': {'type': 'boolean'},
                          'lastCheck': {'type': 'integer'},
                          'state': {'type': 'string'},
                          'name': {'type': 'string'}}

    def __init__(self, params):
        super(SeyrenAlert, self).__init__(params)


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

        self._url = url.rstrip('/')
        self._session = requests.Session()
        self._session.headers = {'User-Agent': 'PySeyrenClient-{}'.format(VERSION)}
        if auth is not None:
            self._session.auth = auth

    def _api_call(self, method, url, params=None, data=None, headers=None):
        ''' Make a call to the API
        :param method: Requests recognized HTTP method.
        :type method: string
        :param url: URL to call
        :type url: string
        :param params: Parameters to pass with the HTTP request.
        :tyep params: dict
        '''
        req = requests.Request(url=url, method=method.upper(), params=params, data=data,
                               headers=headers)
        preq = self._session.prepare_request(req)
        resp = self._session.send(preq)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return resp.content

    def _get_subs(self, data):
        ''' Create subscriptions based on API response data
        :param data: check API response data
        '''
        _subs = []
        if 'subscriptions' in data and data['subscriptions']:
            _subs = [SeyrenSubscription(sub_data) for sub_data in data['subscriptions']]
        return _subs

    def get_metric_count(self, path):
        ''' Get the number of metrics that match the given path
        :param path: metric path e.g.: host.path.metric.xxx
        :type path: string
        :returns: number of matching metrics
        :rtype: int
        '''
        query_url = '{}/api/metrics/{}/total'.format(self._url, path)
        response = self._api_call('GET', query_url)
        return int(response[path])

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

    def get_checks(self, state=None, enabled=None, name=None, fields=None, regexes=None):
        ''' Gets all configured checks
        :param state: State of the check
        state
        enabled
        name
        fields
        regexes
        '''
        params = {}
        checks = []
        checks_data = self._api_call('GET', self._url + '/api/checks', params=urlencode(params))
        for check_data in checks_data['values']:
            subscriptions = self._get_subs(check_data)
            del check_data['subscriptions']
            checks.append(SeyrenCheck(check_data, subscriptions))
        return checks

    def get_check(self, checkId):
        ''' Gets a check given its id
        :param checkId: Seyren ID
        '''
        try:
            check_data = self._api_call('GET', self._url + '/api/checks/{}'.format(checkId))
        except requests.HTTPError, _exp:
            print 'Check {} {}'.format(checkId, _exp.response.reason)
            return None
        subscriptions = self._get_subs(check_data)
        del check_data['subscriptions']
        return SeyrenCheck(check_data, subscriptions)

    def create_check(self, check):
        ''' Send POST to /api/checks with new check info.
        It will also verify the check already exists in order
        to not create duplicates (checkId required)
        :params check: SeyrenCheck object
        '''
        try:
            _payload = json.dumps(check.post_data())
            headers = {'content-type': 'application/json'}
            self._api_call('POST', self._url + '/api/checks', data=_payload, headers=headers)
        except requests.HTTPError, _exp:
            print 'Error creating check {}: {}'.format(check.name, _exp.response.reason)

    def get_chart_for_target(self, target):
        pass

