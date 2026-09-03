from enum import Enum


class Vendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    ARUBA_AOS_CX = "aruba_aos_cx"
    ARUBA_AOS_S = "aruba_aos_s"


class UnsupportedVendorError(ValueError):
    def __init__(self, vendor: Vendor) -> None:
        self.vendor = vendor
        super().__init__(f"vendor is not supported: {vendor.value}")
