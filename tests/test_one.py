import sys, os

# make sure we import the seyren client source from our directory
sys.path.insert(0, os.path.realpath(os.path.dirname(__file__)+"/.."))

import pytest
import seyren
import json

@pytest.fixture
def seyren_client():
    sc = seyren.SeyrenClient(url='http://seyren.home.lan:8081')
    assert sc is not None
    return sc

@pytest.mark.integration
def test_get_metric_count(seyren_client):
    metric_count = seyren_client.get_metric_count('nas.cpu.*')
    assert metric_count == 14

@pytest.mark.integration
def test_get_alerts(seyren_client):

    alerts = seyren_client.get_alerts()

    for alert in alerts:
        assert isinstance(alert, seyren.SeyrenAlert)

    assert len(alerts) == 83
    alert_ids = [alert.id for alert in alerts]
    assert len(set(alert_ids)) == 83


def test_subscription_argument_validation():
    sub = seyren.SeyrenSubscription({})

    # Not set values are None
    assert sub.enabled == None

    # Setting incorrect value raises
    with pytest.raises(seyren.SeyrenDataValidationError):
        sub.enabled = "True"

    # Setting/getting works
    sub.enabled = True
    assert sub.enabled == True
    sub.enabled = False
    assert sub.enabled == False

    # Deletion resets the value to None
    del sub.enabled
    assert sub.enabled == None

def test_check_data_validation():

    with pytest.raises(seyren.SeyrenDataValidationError):
        seyren.SeyrenCheck({'checkId': 'zzz'})

    check = seyren.SeyrenCheck({})

    assert check.checkId == None
    check.checkId = "deadbeef"
    assert check.checkId == "deadbeef"
