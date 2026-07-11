"""Code Generator — from schema + objects to server stub and structs.

Supports C (structs + server) and Python (asyncio server + client) output.
"""

from dataclasses import dataclass, field
from typing import Any

from .schema import ProtocolSchema, MessageType, ProtoField
from .objects import ObjectRecovery
from .hierarchy import HierarchicalModel


CPRAGMA = """
#pragma pack(push, 1)
"""


FIELD_C_MAP = {
    "uint8": "uint8_t",
    "uint16": "uint16_t",
    "uint32": "uint32_t",
    "uint64": "uint64_t",
    "float": "float",
    "double": "double",
    "magic": "uint32_t",
    "bytes": "uint8_t",
}


@dataclass
class CodeGenContext:
    server_port: int = 9999
    header_guard: str = "GENERATED_PROTOCOL_H"
    struct_defs: list[str] = field(default_factory=list)
    codec_funcs: list[str] = field(default_factory=list)
    include_stdlib: bool = True


class CodeGenerator:
    def __init__(self, schema: ProtocolSchema, recovery: ObjectRecovery | None = None):
        self.schema = schema
        self.recovery = recovery
        self.ctx = CodeGenContext()
        if schema.server_port:
            self.ctx.server_port = schema.server_port

    def _field_to_c(self, f: ProtoField, parent: str) -> tuple[str, str, int]:
        ctype = FIELD_C_MAP.get(f.type_hint, "uint8_t")
        hint = f.semantic_hint or f"field_{f.offset}"
        name = hint.replace(" ", "_").lower()
        if not name:
            name = f"field_{f.offset}"
        # Ensure unique name
        return ctype, name, f.size

    def _generate_struct_header(self) -> str:
        lines = [
            f"#ifndef {self.ctx.header_guard}",
            f"#define {self.ctx.header_guard}",
            "",
            "#include <stdint.h>",
            "#include <stddef.h>",
            "#include <string.h>",
            "#include <arpa/inet.h>",
            "",
            CPRAGMA.strip(),
            "",
        ]
        return "\n".join(lines)

    def _generate_structs(self) -> list[str]:
        structs = []
        for mt in self.schema.messages:
            # Only emit meaningful header fields; rest goes to data[]
            header_fields: list[tuple[str, str, int]] = []
            data_offset = mt.total_len

            for f in mt.fields:
                if f.offset >= 32:  # beyond sample data reach
                    data_offset = f.offset
                    break
                if f.type_hint == "magic" and f.offset > 0:
                    # merge consecutive magic/padding after header
                    data_offset = f.offset
                    break
                if f.type_hint == "magic" and f.offset == 0:
                    ctype = "uint32_t"
                    name = "msg_type"
                    header_fields.append((ctype, name, 4))
                elif f.type_hint == "uint64":
                    ctype = "uint64_t"
                    name = f"field_{f.offset}"
                    header_fields.append((ctype, name, 8))
                elif f.type_hint == "uint32":
                    ctype = "uint32_t"
                    name = f"field_{f.offset}"
                    header_fields.append((ctype, name, 4))
                elif f.type_hint == "uint16":
                    ctype = "uint16_t"
                    name = f"field_{f.offset}"
                    header_fields.append((ctype, name, 2))
                elif f.type_hint == "uint8":
                    ctype = "uint8_t"
                    name = f"field_{f.offset}"
                    header_fields.append((ctype, name, 1))
                elif f.type_hint == "float":
                    ctype = "float"
                    name = f"field_{f.offset}"
                    header_fields.append((ctype, name, 4))
                else:
                    data_offset = f.offset
                    break
                data_offset = f.offset + f.size

            remaining = max(0, mt.total_len - data_offset)

            lines = [f"struct Message_{mt.type_id} {{"]
            if mt.sample_payload:
                msg_type_val = int.from_bytes(mt.sample_payload[:4], 'little')
                lines.append(f"    // type_id={mt.type_id} (0x{msg_type_val:x})")

            for ctype, name, size in header_fields:
                lines.append(f"    {ctype} {name};")

            if remaining > 0:
                lines.append(f"    uint8_t data[{remaining}];")

            lines.append(f"}} __attribute__((packed));")
            lines.append(f"static_assert(sizeof(struct Message_{mt.type_id}) == {mt.total_len}, "
                         f"\"Message_{mt.type_id} size mismatch\");")
            lines.append(f"typedef struct Message_{mt.type_id} Message_{mt.type_id};")
            lines.append("")
            structs.append("\n".join(lines))

        return structs

    def _generate_codecs(self) -> list[str]:
        codecs = []
        for mt in self.schema.messages:
            msg_type = f"Message_{mt.type_id}"

            # Helper: parse function
            lines = [
                f"static inline int {msg_type}_decode(const uint8_t *data, size_t len, {msg_type} *out) {{",
                f"    if (len < sizeof({msg_type})) return -1;",
                f"    memcpy(out, data, sizeof({msg_type}));",
                f"    return 0;",
                f"}}",
                "",
                f"static inline size_t {msg_type}_encode(const {msg_type} *in, uint8_t *buf, size_t cap) {{",
                f"    if (cap < sizeof({msg_type})) return 0;",
                f"    memcpy(buf, in, sizeof({msg_type}));",
                f"    return sizeof({msg_type});",
                f"}}",
                "",
            ]
            codecs.append("\n".join(lines))
        return codecs

    def _generate_server_stub(self) -> str:
        lines = [
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <unistd.h>",
            "#include <sys/socket.h>",
            "#include <netinet/in.h>",
            "#include \"protocol.h\"",
            "",
            "static int server_fd;",
            "",
            f"#define PORT {self.ctx.server_port}",
            f"#define BUF_SIZE 65535",
            "",
            "static int server_init(void) {",
            "    struct sockaddr_in addr = {",
            "        .sin_family = AF_INET,",
            "        .sin_port = htons(PORT),",
            "        .sin_addr = { htonl(INADDR_ANY) }",
            "    };",
            "    server_fd = socket(AF_INET, SOCK_DGRAM, 0);",
            "    if (server_fd < 0) { perror(\"socket\"); return -1; }",
            "    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {",
            "        perror(\"bind\"); close(server_fd); return -1;",
            "    }",
            "    fprintf(stderr, \"[server] listening on port %d\\n\", PORT);",
            "    return 0;",
            "}",
            "",
        ]

        # Generate handler for each message type
        dispatch_cases = []
        for mt in self.schema.messages:
            msg_type = f"Message_{mt.type_id}"
            case = [
                f"    case 0x{mt.type_id:08x}: {{",
                f"        {msg_type} msg;",
                f"        if ({msg_type}_decode(buf, n, &msg) == 0) {{",
                f"            // TODO: handle message type {mt.type_id}",
                f"            // respond with compatible struct",
                f"            uint8_t resp[sizeof({msg_type})];",
                f"            size_t rlen = {msg_type}_encode(&msg, resp, sizeof(resp));",
                f"            sendto(server_fd, resp, rlen, 0,",
                f"                   (struct sockaddr*)&cli, sizeof(cli));",
                f"        }}",
                f"        break;",
                f"    }}",
            ]
            dispatch_cases.append("\n".join(case))

        lines.append("static void handle_packet(const uint8_t *buf, size_t n,")
        lines.append("                         struct sockaddr_in *cli) {")
        lines.append(f"    if (n < 4) return;")
        lines.append("    uint32_t msg_type = *(const uint32_t*)buf;")
        lines.append("    switch (msg_type) {")
        for c in dispatch_cases:
            lines.append(c)
        lines.append("    default:")
        lines.append('        fprintf(stderr, "[server] unknown msg_type=0x%x\\n", msg_type);')
        lines.append("        break;")
        lines.append("    }")
        lines.append("}")
        lines.append("")

        # Main loop
        lines.extend([
            "int main(void) {",
            "    if (server_init() < 0) return 1;",
            "    uint8_t buf[BUF_SIZE];",
            "    struct sockaddr_in cli;",
            "    socklen_t cli_len = sizeof(cli);",
            "    fprintf(stderr, \"[server] running\\n\");",
            "    for (;;) {",
            "        ssize_t n = recvfrom(server_fd, buf, sizeof(buf), 0,",
            "                             (struct sockaddr*)&cli, &cli_len);",
            "        if (n < 0) { perror(\"recvfrom\"); continue; }",
            "        handle_packet(buf, (size_t)n, &cli);",
            "    }",
            "    close(server_fd);",
            "    return 0;",
            "}",
        ])

        return "\n".join(lines)

    def _extract_entity_sizes(self) -> list[tuple[int, str]]:
        sizes: list[tuple[int, str]] = []
        seen: set[int] = set()
        if not self.recovery:
            return sizes
        for obj in self.recovery.objects:
            if obj.untracked or obj.is_ghost:
                continue
            sz = obj.size
            if sz in seen:
                continue
            if len(obj.network_sends) >= 50:
                sizes.append((sz, "PacketBuffer"))
            elif len(obj.copies_out) >= 50 and not obj.network_sends:
                if sz > 1024:
                    sizes.append((sz, "FrameBuffer"))
                else:
                    sizes.append((sz, "Entity"))
            elif len(obj.copies_in) >= 50:
                sizes.append((sz, "SerializedEntity"))
            else:
                if sz == 4096:
                    sizes.append((sz, "FrameBuffer"))
                elif sz == 4100:
                    sizes.append((sz, "SerializedEntity"))
                else:
                    continue
            seen.add(sz)
        return sizes

    def _generate_entity_structs(self) -> str:
        sizes = self._extract_entity_sizes()
        if not sizes:
            return ""

        lines = ["", "// --- Inferred object structs (from allocation patterns) ---", ""]
        for size, hint in sizes:
            name = f"Inferred_{hint}"
            struct_size = size
            lines.append(f"struct {name} {{")
            lines.append(f"    uint8_t data[{struct_size}];")
            lines.append(f"}} __attribute__((packed));")
            lines.append(f"typedef struct {name} {name};")
            lines.append(f"#define {name.upper()}_SIZE {struct_size}")
            lines.append("")
        return "\n".join(lines)

    def _generate_makefile(self) -> str:
        return """CC = gcc
CFLAGS = -O2 -Wall -Wextra

all: server

server: server.c protocol.h
\t$(CC) $(CFLAGS) -o server server.c

clean:
\trm -f server

.PHONY: all clean
"""

    def generate(self, output_dir: str = ".") -> dict[str, str]:
        files: dict[str, str] = {}

        # protocol.h
        h_lines = [self._generate_struct_header()]
        structs = self._generate_structs()
        entity_structs = self._generate_entity_structs()
        h_lines.extend(structs)
        h_lines.append(entity_structs)
        h_lines.append("")
        for codec in self._generate_codecs():
            h_lines.append(codec)
        h_lines.append("#endif /* " + self.ctx.header_guard + " */\n")
        files["protocol.h"] = "\n".join(h_lines)

        # server.c
        files["server.c"] = self._generate_server_stub()

        # Makefile
        files["Makefile"] = self._generate_makefile()

        return files

    def summary(self) -> str:
        files = self.generate()
        lines = [f"=== Code Generation ==="]
        for name, content in files.items():
            clines = content.count('\n')
            lines.append(f"  {name}: {clines} lines")
        entity_sizes = self._extract_entity_sizes()
        if entity_sizes:
            lines.append(f"  Inferred object types: {len(entity_sizes)}")
            for size, hint in entity_sizes:
                lines.append(f"    struct {hint}: {size} bytes")
        return "\n".join(lines)


FIELD_PYTHON_TYPE = {
    "uint8": "int",
    "uint16": "int",
    "uint32": "int",
    "uint64": "int",
    "float": "float",
    "double": "float",
    "magic": "int",
    "bytes": "bytes",
}

FIELD_PYTHON_UNPACK = {
    1: "<B",
    2: "<H",
    4: "<I",
    8: "<Q",
}

FIELD_PYTHON_FLOAT_UNPACK = {
    4: "<f",
    8: "<d",
}


class PythonCodeGenerator:
    """Generate Python asyncio server + client from schema + hierarchy."""

    def __init__(self, schema: ProtocolSchema, model: HierarchicalModel | None = None):
        self.schema = schema
        self.model = model

    def _field_meta(self) -> list[dict]:
        """Build field metadata dict per message type."""
        meta = []
        for mt in self.schema.messages:
            fields = []
            for f in mt.fields:
                fields.append({
                    "offset": f.offset,
                    "size": f.size,
                    "type": f.type_hint,
                    "semantic": f.semantic_hint or f"field_{f.offset}",
                    "constant": f.constant_value,
                })
            meta.append({
                "type_id": mt.type_id,
                "size": mt.total_len,
                "count": mt.count,
                "fields": fields,
                "sample": mt.sample_payload.hex() if mt.sample_payload else "",
            })
        return meta

    def _generate_protocol_py(self) -> str:
        """Generate protocol.py with dataclasses + pack/unpack."""
        lines = [
            '"""Auto-generated protocol definitions."""',
            "",
            "import struct",
            "from dataclasses import dataclass",
            "from typing import Optional",
            "",
            "",
        ]

        for mt in self.schema.messages:
            class_name = f"Msg{mt.type_id}"
            lines.append(f"MSG_{mt.type_id}_SIZE = {mt.total_len}")
            lines.append("")

            # Dataclass
            lines.append(f"@dataclass")
            lines.append(f"class {class_name}:")
            lines.append(f"    type_id: int = {mt.type_id}")

            non_const_fields = [f for f in mt.fields
                                if not (f.constant_value is not None and f.offset == 0)]
            for f in non_const_fields:
                py_type = FIELD_PYTHON_TYPE.get(f.type_hint, "bytes")
                fname = f.semantic_hint or f"field_{f.offset}"
                fname = fname.replace(" ", "_").lower()
                lines.append(f"    {fname}: {py_type} = 0")

            lines.append("")
            lines.append(f"    @staticmethod")
            lines.append(f"    def unpack(data: bytes) -> '{class_name}':")
            lines.append(f'        """Parse from wire format."""')
            lines.append(f"        if len(data) < {mt.total_len}:")
            lines.append(f'            raise ValueError(f"expected {mt.total_len}B, got {{len(data)}}B")')
            lines.append(f"        return {class_name}(")
            for f in mt.fields:
                fname = f.semantic_hint or f"field_{f.offset}"
                fname = fname.replace(" ", "_").lower()
                if f.type_hint == "float":
                    unpack_fmt = FIELD_PYTHON_FLOAT_UNPACK.get(f.size)
                else:
                    unpack_fmt = FIELD_PYTHON_UNPACK.get(f.size, None)
                if unpack_fmt:
                    lines.append(f"            {fname}=struct.unpack_from('{unpack_fmt}', data, {f.offset})[0],")
                else:
                    lines.append(f"            {fname}=data[{f.offset}:{f.offset + f.size}],")
            lines.append("        )")
            lines.append("")
            lines.append(f"    def pack(self) -> bytes:")
            lines.append(f'        """Serialize to wire format."""')
            lines.append(f"        data = bytearray({mt.total_len})")
            for f in mt.fields:
                fname = f.semantic_hint or f"field_{f.offset}"
                fname = fname.replace(" ", "_").lower()
                if f.type_hint == "float":
                    pack_fmt = FIELD_PYTHON_FLOAT_UNPACK.get(f.size)
                else:
                    pack_fmt = FIELD_PYTHON_UNPACK.get(f.size, None)
                if f.constant_value is not None:
                    if pack_fmt:
                        lines.append(f"        struct.pack_into('{pack_fmt}', data, {f.offset}, {f.constant_value})")
                    else:
                        lines.append(f"        data[{f.offset}:{f.offset + f.size}] = ({f.constant_value}).to_bytes({f.size}, 'little')")
                elif pack_fmt:
                    lines.append(f"        struct.pack_into('{pack_fmt}', data, {f.offset}, self.{fname})")
                else:
                    lines.append(f"        data[{f.offset}:{f.offset + f.size}] = self.{fname}")
            lines.append(f"        return bytes(data)")
            lines.append("")

        return "\n".join(lines)

    def _generate_server_py(self) -> str:
        """Generate asyncio UDP server."""
        msg_classes = [f"Msg{mt.type_id}" for mt in self.schema.messages]
        lines = [
            '"""Auto-generated protocol server. Run with: python3 server.py"""',
            "",
            "import asyncio",
            "import struct",
            "from protocol import " + ", ".join(msg_classes),
            "",
            f"SERVER_PORT = {self.schema.server_port or 9999}",
            "",
            "MSG_DISPATCH = {",
        ]
        for mt in self.schema.messages:
            lines.append(f"    {mt.type_id}: Msg{mt.type_id}.unpack,")
        lines.extend([
            "}",
            "",
        ])

        if self.model:
            for sys in self.model.systems.values():
                if sys.kind == "deserializer":
                    lines.append(f"# System: {sys.name}")
                    lines.append(f"#   reads {len(sys.inputs)} entity types")
                elif sys.kind == "serializer":
                    lines.append(f"# System: {sys.name}")
                    lines.append(f"#   writes {len(sys.outputs)} entity types")

        lines.append("")
        lines.append("class ProtocolHandler:")
        lines.append("    '''Handle incoming protocol messages.'''")

        lines.append("")
        for mt in self.schema.messages:
            class_name = f"Msg{mt.type_id}"
            lines.append(f"    async def on_{class_name}(self, msg: {class_name},")
            lines.append(f"                                 addr: tuple) -> bytes | None:")
            lines.append(f'        """Handle Msg{mt.type_id}. Return response bytes or None."""')
            if self.model:
                related = [
                    e for e in self.model.entities.values()
                    if e.record_type.size == mt.total_len
                ]
                if related:
                    lines.append(f"        # Entity instances: {len(related)}")
                    for e in related[:3]:
                        lines.append(f"        #   {e.label}: {e.lifecycle.num_updates} updates")
            lines.append(f"        raise NotImplementedError")
            lines.append("")
        lines.append("")
        lines.append("class Server:")
        lines.append("    def __init__(self, handler: ProtocolHandler | None = None):")
        lines.append("        self.handler = handler or ProtocolHandler()")
        lines.append("        self._transport = None")
        lines.append("")
        lines.append("    def connection_made(self, transport):")
        lines.append("        self._transport = transport")
        lines.append("        print(f'[server] listening on port {SERVER_PORT}')")
        lines.append("")
        lines.append("    def datagram_received(self, data: bytes, addr: tuple):")
        lines.append("        if len(data) < 4:")
        lines.append("            return")
        lines.append("        type_id = struct.unpack_from('<I', data, 0)[0]")
        lines.append("        unpack = MSG_DISPATCH.get(type_id)")
        lines.append("        if unpack is None:")
        lines.append("            print(f'[server] unknown type_id={type_id} from {addr}')")
        lines.append("            return")
        lines.append("        msg = unpack(data)")
        lines.append('        coro = self._dispatch(msg, addr)')
        lines.append("        asyncio.create_task(coro)")
        lines.append("")
        lines.append("    async def _dispatch(self, msg, addr):")
        lines.append("        handler_name = f'on_{type(msg).__name__}'")
        lines.append("        handler = getattr(self.handler, handler_name, None)")
        lines.append("        if handler:")
        lines.append("            resp = await handler(msg, addr)")
        lines.append("            if resp:")
        lines.append("                self._transport.sendto(resp, addr)")
        lines.append("")
        lines.append("    def error_received(self, exc):")
        lines.append("        print(f'[server] error: {exc}')")
        lines.append("")
        lines.append("    def connection_lost(self, exc):")
        lines.append("        print(f'[server] connection lost: {exc}'")
        lines.append("              if exc else '[server] done')")
        lines.append("")
        lines.append("")
        lines.append("async def main():")
        lines.append("    print(f'[server] starting on port {SERVER_PORT}')")
        lines.append("    loop = asyncio.get_event_loop()")
        lines.append("    transport, _ = await loop.create_datagram_endpoint(")
        lines.append("        Server,")
        lines.append("        local_addr=('0.0.0.0', SERVER_PORT),")
        lines.append("    )")
        lines.append("    try:")
        lines.append("        await asyncio.Event().wait()")
        lines.append("    except KeyboardInterrupt:")
        lines.append("        pass")
        lines.append("    finally:")
        lines.append("        transport.close()")
        lines.append("")
        lines.append("")
        lines.append('if __name__ == "__main__":')
        lines.append("    asyncio.run(main())")
        lines.append("")

        return "\n".join(lines)

    def _generate_client_py(self) -> str:
        """Generate Python client stub."""
        msg_classes = [f"Msg{mt.type_id}" for mt in self.schema.messages]
        lines = [
            '"""Auto-generated protocol client."""',
            "",
            "import asyncio",
            "import struct",
            "from protocol import " + ", ".join(msg_classes),
            "",
            f"SERVER_ADDR = ('127.0.0.1', {self.schema.server_port or 9999})",
            "",
            "MSG_DISPATCH = {",
        ]
        for mt in self.schema.messages:
            lines.append(f"    {mt.type_id}: Msg{mt.type_id}.unpack,")
        lines.append("}")
        lines.append("")
        lines.append("")
        lines.append("class Client:")
        lines.append("    def __init__(self):")
        lines.append("        self._transport = None")
        lines.append("        self._protocol = None")
        lines.append("")
        lines.append("    async def connect(self):")
        lines.append("        loop = asyncio.get_event_loop()")
        lines.append("        self._transport, self._protocol = await loop.create_datagram_endpoint(")
        lines.append("            asyncio.DatagramProtocol,")
        lines.append("            remote_addr=SERVER_ADDR,")
        lines.append("        )")
        lines.append("")
        for mt in self.schema.messages:
            args_list = []
            for f in mt.fields:
                if not (f.constant_value is not None and f.offset == 0):
                    fname = f.semantic_hint or f"field_{f.offset}"
                    fname = fname.replace(" ", "_").lower()
                    py_type = FIELD_PYTHON_TYPE.get(f.type_hint, "bytes")
                    args_list.append(f"{fname}: {py_type}")
            args_str = ", ".join(args_list)
            class_name = f"Msg{mt.type_id}"
            lines.append(f"    async def send_{class_name}(self, {args_str}):")
            lines.append(f"        '''Send Msg{mt.type_id} to server.'''")
            lines.append(f"        msg = {class_name}(")
            for f in mt.fields:
                if not (f.constant_value is not None and f.offset == 0):
                    fname = f.semantic_hint or f"field_{f.offset}"
                    fname = fname.replace(" ", "_").lower()
                    lines.append(f"            {fname}={fname},")
            lines.append("        )")
            lines.append(f"        self._transport.sendto(msg.pack())")
            lines.append("")
        lines.append("    def close(self):")
        lines.append("        if self._transport:")
        lines.append("            self._transport.close()")
        lines.append("")

        return "\n".join(lines)

    def generate(self, output_dir: str = ".") -> dict[str, str]:
        files = {
            "protocol.py": self._generate_protocol_py(),
            "server.py": self._generate_server_py(),
            "client.py": self._generate_client_py(),
        }
        return files

    def summary(self) -> str:
        files = self.generate()
        lines = ["=== Python Code Generation ==="]
        for name, content in files.items():
            clines = content.count('\n')
            lines.append(f"  {name}: {clines} lines")
        return "\n".join(lines)
