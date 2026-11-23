"""Generated OpenShell protobuf modules (interceptor/gen, built from proto/ by `make gen`)."""
import sys
from pathlib import Path

_GEN = Path(__file__).parent / "gen"
if str(_GEN) not in sys.path:
    sys.path.insert(0, str(_GEN))  # generated modules import each other by bare name

import extension_pb2  # noqa: E402,F401
import gateway_interceptor_pb2  # noqa: E402,F401
import gateway_interceptor_pb2_grpc  # noqa: E402,F401
import openshell_pb2  # noqa: E402,F401
import sandbox_pb2  # noqa: E402,F401
