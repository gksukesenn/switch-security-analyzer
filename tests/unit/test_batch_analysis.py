from types import SimpleNamespace

import pytest

from src.domain.vendors import Vendor
from src.services.batch_analysis import (
    MAX_BATCH_DEVICES,
    BatchAnalysisService,
    BatchDeviceInput,
    InvalidBatchError,
    VendorStatistics,
)


CISCO_SCORED_CONFIG = """hostname CISCO-01
ip dhcp snooping
ip dhcp snooping vlan 10
ip arp inspection vlan 10
ip http server
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
 ip verify source
!
line vty 0 4
 transport input ssh
"""

ARUBA_UNSCORED_CONFIG = """hostname ARUBA-01
dhcpv4-snooping
vlan 10
 dhcpv4-snooping
!
interface 1/1/1
 no routing
 vlan access 20
 spanning-tree port-type admin-edge
!
"""


def test_mixed_vendor_batch_aggregates_without_averaging_scores():
    result = BatchAnalysisService().analyze([
        BatchDeviceInput(
            "cisco-01", Vendor.CISCO_IOS, CISCO_SCORED_CONFIG
        ),
        BatchDeviceInput(
            "aruba-01", Vendor.ARUBA_AOS_CX, ARUBA_UNSCORED_CONFIG
        ),
    ])

    assert [device.device_id for device in result.devices] == [
        "cisco-01",
        "aruba-01",
    ]
    assert [device.analysis.config.vendor for device in result.devices] == [
        "cisco_ios",
        "aruba_aos_cx",
    ]
    assert result.devices[0].analysis.posture.score == 85.0
    assert result.devices[1].analysis.posture.score is None
    assert result.statistics.total_devices == 2
    assert result.statistics.total_findings == 3
    assert result.statistics.scored_devices == 1
    assert result.statistics.unscored_devices == 1
    assert result.statistics.by_vendor["cisco_ios"] == (
        VendorStatistics(1, 1, 1, 0)
    )
    assert result.statistics.by_vendor["aruba_aos_cx"] == (
        VendorStatistics(1, 2, 0, 1)
    )
    assert result.statistics.by_category == {
        "DHCP_SPOOFING": 1,
        "MGMT": 1,
        "STP": 1,
    }
    assert not hasattr(result.statistics, "average_posture_score")


def test_batch_service_sequentially_delegates_to_single_device_service():
    calls = []

    class RecordingAnalysisService:
        def analyze(self, config, vendor):
            calls.append((config, vendor))
            return SimpleNamespace(
                findings=(),
                posture=SimpleNamespace(score=None),
            )

    devices = [
        BatchDeviceInput("second", Vendor.ARUBA_AOS_CX, "hostname A"),
        BatchDeviceInput("first", Vendor.CISCO_IOS, "hostname C"),
    ]

    result = BatchAnalysisService(RecordingAnalysisService()).analyze(devices)

    assert calls == [
        ("hostname A", Vendor.ARUBA_AOS_CX),
        ("hostname C", Vendor.CISCO_IOS),
    ]
    assert [device.device_id for device in result.devices] == [
        "second",
        "first",
    ]


@pytest.mark.parametrize(
    "devices",
    [
        [],
        [
            BatchDeviceInput("duplicate", Vendor.CISCO_IOS, "hostname A"),
            BatchDeviceInput("duplicate", Vendor.ARUBA_AOS_CX, "hostname B"),
        ],
        [
            BatchDeviceInput(str(index), Vendor.CISCO_IOS, "hostname A")
            for index in range(MAX_BATCH_DEVICES + 1)
        ],
    ],
)
def test_batch_service_rejects_invalid_batch_inputs(devices):
    with pytest.raises(InvalidBatchError):
        BatchAnalysisService().analyze(devices)
