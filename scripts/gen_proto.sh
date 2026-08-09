#!/usr/bin/env bash
#
# Regenerate the Python protobuf bindings from proto/keystork.proto.
#
# The generated module is committed (client/keystork/_proto/keystork_pb2.py) so
# that the client is pip-installable without a protoc on the machine. Run this
# after editing the .proto and commit the result.
#
# The server's C++ bindings are NOT generated here: the server's CMake build
# runs protoc itself, because the generated .cc must match the protobuf runtime
# it is linked against.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/client/keystork/_proto"

command -v protoc >/dev/null || {
    echo "protoc not found (dnf install protobuf-compiler)" >&2
    exit 1
}

mkdir -p "$out"
protoc --proto_path="$root/proto" --python_out="$out" "$root/proto/keystork.proto"

# protoc emits a top-level `import`-free module here (keystork.proto has no
# dependencies), so no import rewriting is needed.

echo "wrote $out/keystork_pb2.py"
echo "protoc: $(protoc --version)"
