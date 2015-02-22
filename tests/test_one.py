import sys, os

# make sure we import the seyren client source from our directory
sys.path.insert(0, os.path.realpath(os.path.dirname(__file__)+"/.."))

import pytest
import seyren
import json


def test_create_client():
    sc = seyren.SeyrenClient(url='http://seyren.home.lan:8081')
    assert sc is not None

@pytest.mark.integration
def test_get_alerts():
    sc = seyren.SeyrenClient(url='http://seyren.home.lan:8081')

    alerts = sc.get_alerts()

    for alert in alerts:
        assert isinstance(alert, seyren.SeyrenAlert)

    assert len(alerts) == 83
    alert_ids = [alert.id for alert in alerts]
    assert len(set(alert_ids)) == 83

