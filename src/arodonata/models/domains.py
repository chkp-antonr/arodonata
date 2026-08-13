"""Domain and Gateway models for arodonata."""

from .common import BaseModelWithRaw


class Domain(BaseModelWithRaw):
    """Cached domain information."""

    uid: str
    name: str
    active_mds: str
    active_ip: str
    active_server: str
    standby_ips: list[str] = []
    standby_servers: list[str] = []
    mgmt_name: str
    is_mdm: bool = False


class Gateway(BaseModelWithRaw):
    """Cached gateway/server asset."""

    uid: str
    name: str
    type: str
    ip_address: str
    ssh_ip: str = ""
    domain_name: str = ""
    mgmt_name: str
    parent_uid: str | None = None


class Host(BaseModelWithRaw):
    """Cached host object."""

    uid: str
    name: str
    ip_address: str = ""
    mgmt_name: str
    domain_name: str = ""


class Network(BaseModelWithRaw):
    """Cached network object."""

    uid: str
    name: str
    subnet4: str = ""
    subnet_mask: str = ""
    mgmt_name: str
    domain_name: str = ""


class Group(BaseModelWithRaw):
    """Cached group object."""

    uid: str
    name: str
    member_uids: list[str] = []
    mgmt_name: str
    domain_name: str = ""
