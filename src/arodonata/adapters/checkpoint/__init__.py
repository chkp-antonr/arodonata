"""Check Point Management Web API adapter package (`arodonata.adapters.checkpoint`)."""

from arodonata.adapters.checkpoint.client import AMgmtClient
from arodonata.adapters.checkpoint.pager import (
    BOUNDARY_WINDOW_RADIUS,
    DEFAULT_PAGE_LIMIT,
    MAX_PAGE_LIMIT,
    TASK_QUERY_COMMANDS,
    paginate_objects,
)
from arodonata.adapters.checkpoint.rate_limiter import LoginGate, RateLimiter
from arodonata.adapters.checkpoint.sessions import (
    SYSTEM_DOMAIN_SENTINEL,
    LoginCoordinator,
    SessionCleaner,
    normalize_domain_key,
    parse_domain_entry,
)
from arodonata.adapters.checkpoint.task_waiter import (
    TASK_FAILURE_STATUSES,
    TASK_IN_PROGRESS_STATUSES,
    TASK_SUCCESS_STATUSES,
    TaskWaiter,
    extract_task_ids,
)
from arodonata.adapters.checkpoint.tls import (
    KnownHostEntry,
    TrustPolicy,
    TrustStore,
    compute_der_fingerprint,
    format_host_port,
    normalize_fingerprint,
    parse_tls_fingerprints,
)
from arodonata.adapters.checkpoint.transport import (
    KEEPALIVE_IDLE_LIMIT_SECONDS,
    ApiTransport,
    FingerprintTCPConnector,
    PooledSocketEntry,
    RawHttpResponse,
    VerifiedConnectionPool,
    extract_peer_der_cert,
    is_readonly_poolable_command,
    verify_transport_peer_certificate,
)

__all__ = [
    "BOUNDARY_WINDOW_RADIUS",
    "DEFAULT_PAGE_LIMIT",
    "KEEPALIVE_IDLE_LIMIT_SECONDS",
    "MAX_PAGE_LIMIT",
    "SYSTEM_DOMAIN_SENTINEL",
    "TASK_FAILURE_STATUSES",
    "TASK_IN_PROGRESS_STATUSES",
    "TASK_QUERY_COMMANDS",
    "TASK_SUCCESS_STATUSES",
    "AMgmtClient",
    "ApiTransport",
    "FingerprintTCPConnector",
    "KnownHostEntry",
    "LoginCoordinator",
    "LoginGate",
    "PooledSocketEntry",
    "RateLimiter",
    "RawHttpResponse",
    "SessionCleaner",
    "TaskWaiter",
    "TrustPolicy",
    "TrustStore",
    "VerifiedConnectionPool",
    "compute_der_fingerprint",
    "extract_peer_der_cert",
    "extract_task_ids",
    "format_host_port",
    "is_readonly_poolable_command",
    "normalize_domain_key",
    "normalize_fingerprint",
    "paginate_objects",
    "parse_domain_entry",
    "parse_tls_fingerprints",
    "verify_transport_peer_certificate",
]
