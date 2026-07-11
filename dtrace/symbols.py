"""Symbol Resolution — from binary to type names."""

import subprocess
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.constants import DW_TAG_structure_type, DW_TAG_class_type, DW_AT_name, DW_AT_byte_size


class SymbolResolver:
    """Resolves allocation sizes to type names from binary symbols and DWARF."""

    def __init__(self, binary_path: str | None = None):
        self.binary_path = binary_path
        self._size_map: dict[int, list[str]] = {}  # size → [type_names]
        self._symbols: dict[str, list[tuple[int, int]]] = {}  # name → [(addr, size)]

        if binary_path:
            self._load_elf()

    def _load_elf(self):
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                self._parse_dwarf(elffile)
            self._parse_nm()
        except Exception as e:
            import sys
            print(f"[symbols] ELF load error: {e}", file=sys.stderr)

    def _parse_dwarf(self, elffile):
        if not elffile.has_dwarf_info():
            return
        dwarfinfo = elffile.get_dwarf_info()
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag in (DW_TAG_structure_type, DW_TAG_class_type):
                    name = die.attributes.get(DW_AT_name)
                    byte_size = die.attributes.get(DW_AT_byte_size)
                    if name and byte_size:
                        self._size_map.setdefault(byte_size.value, []).append(name.value.decode())

    def _parse_nm(self):
        try:
            out = subprocess.run(
                ["nm", "--defined-only", "--size-sort", self.binary_path],
                capture_output=True, text=True, timeout=5
            )
            for line in out.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3 and parts[1] in ('D', 'd', 'B', 'b', 'T', 't'):
                    try:
                        addr = int(parts[0], 16)
                        size = int(parts[1], 16) if len(parts[0]) == 8 else 0
                        name = parts[2]
                        self._symbols.setdefault(name, []).append((addr, size))
                    except ValueError:
                        pass
        except Exception:
            pass

    def resolve_size(self, size: int) -> str | None:
        """Map allocation size → type name."""
        names = self._size_map.get(size)
        if names:
            return names[0]
        return None

    def resolve_addr(self, addr: int) -> str | None:
        """Map address → nearest symbol."""
        best = None
        best_dist = 1 << 64
        for name, entries in self._symbols.items():
            for sym_addr, sym_size in entries:
                if sym_addr <= addr < sym_addr + sym_size:
                    return name
                dist = abs(sym_addr - addr)
                if dist < best_dist:
                    best_dist = dist
                    best = name
        return best

    def resolve(self, obj) -> str | None:
        """Resolve object to type name using size first, then address."""
        name = self.resolve_size(obj.size)
        if name:
            return name
        name = self.resolve_addr(obj.addr)
        if name:
            return name
        return None

    def size_map_summary(self) -> str:
        if not self._size_map:
            return "  (no DWARF info)"
        lines = ["Size → Type mappings:"]
        for size in sorted(self._size_map):
            names = ", ".join(self._size_map[size])
            lines.append(f"  {size:4d}B → {names}")
        return "\n".join(lines)
