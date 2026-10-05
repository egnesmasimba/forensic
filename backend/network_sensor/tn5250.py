"""Stored TN5250 display streams. Orders follow the 5250 data stream, not a live session."""
from __future__ import annotations

ROWS = 24
COLUMNS = 80
CELLS = ROWS * COLUMNS

# Commands and orders from the 5250 Functions Reference, as used by the public TN5250 decoders.
CLEAR_COMMANDS = {0x40: "clear_unit", 0x20: "clear_unit_alternate"}
WRITE_TO_DISPLAY = 0x11
ESCAPE = 0x04
FCW_TYPES = {0x80, 0x81, 0x82, 0x84, 0x85, 0x86, 0x88, 0x89, 0x8A, 0xB1}

CAPABILITY = (
    "Stored TN5250 clear-unit and write-to-display streams on a 24x80 screen, "
    "including SBA, IC, MC, RA, EA, and SF. Structured fields, SNA, and MPTN are not reconstructed."
)


def _ebcdic(value: int) -> str:
    return bytes([value]).decode("cp037") if value >= 0x40 else " "


def _position(row: int, column: int) -> int | None:
    if 1 <= row <= ROWS and 1 <= column <= COLUMNS:
        return (row - 1) * COLUMNS + (column - 1)
    return None


class Screen:
    def __init__(self):
        self.cells = [" "] * CELLS
        self.address = 0
        self.cursor = [1, 1]
        self.partial = False

    def clear(self):
        self.cells = [" "] * CELLS
        self.address = 0
        self.cursor = [1, 1]

    def snapshot(self) -> dict:
        return {
            "kind": "5250_subset",
            "partial": self.partial,
            "cursor": self.cursor[:],
            "rows": ["".join(self.cells[start:start + COLUMNS]).rstrip() for start in range(0, CELLS, COLUMNS)],
        }

    def _repeat(self, target: int, character: str) -> None:
        if target >= CELLS:
            self.partial = True
            return
        while self.address != target:
            self.cells[self.address] = character
            self.address = (self.address + 1) % CELLS

    def orders(self, data: bytes, index: int) -> int:
        while index < len(data):
            value = data[index]
            if value == ESCAPE:
                return index
            if value == 0x11:  # SBA: row, column
                if index + 3 > len(data):
                    self.partial = True
                    return len(data)
                target = _position(data[index + 1], data[index + 2])
                index += 3
                if target is None:
                    self.partial = True
                    return len(data)
                self.address = target
            elif value in (0x13, 0x14):  # IC, MC
                if index + 3 > len(data):
                    self.partial = True
                    return len(data)
                target = _position(data[index + 1], data[index + 2])
                index += 3
                if target is None:
                    self.partial = True
                    return len(data)
                self.cursor = [target // COLUMNS + 1, target % COLUMNS + 1]
                if value == 0x14:
                    self.address = target
            elif value == 0x02:  # RA
                if index + 4 > len(data):
                    self.partial = True
                    return len(data)
                target = _position(data[index + 1], data[index + 2])
                character = _ebcdic(data[index + 3])
                index += 4
                if target is None:
                    self.partial = True
                    return len(data)
                self._repeat(target, character)
            elif value == 0x03:  # EA
                if index + 3 > len(data):
                    self.partial = True
                    return len(data)
                target = _position(data[index + 1], data[index + 2])
                index += 3
                if target is None:
                    self.partial = True
                    return len(data)
                self._repeat(target, " ")
            elif value == 0x1D:  # SF: optional FFW, optional FCWs, attribute, field length
                index += 1
                if index >= len(data):
                    self.partial = True
                    return len(data)
                if data[index] & 0x40:
                    index += 2
                seen = 0
                while index < len(data) and data[index] in FCW_TYPES and seen < 8:
                    index += 2
                    seen += 1
                index += 3  # attribute and two-byte field length; length is a screen size, not stream data
                if index > len(data):
                    self.partial = True
                    return len(data)
            elif value in (0x01, 0x10, 0x12, 0x15):
                self.partial = True
                return len(data)
            else:
                self.cells[self.address] = _ebcdic(value)
                self.address = (self.address + 1) % CELLS
                index += 1
        return index


def _records(data: bytes) -> list[bytes]:
    """Split a GDS 0x12A0 record when the length matches; otherwise keep the bytes."""
    if len(data) >= 6 and int.from_bytes(data[:2], "big") == len(data) and data[2:4] == b"\x12\xa0":
        return [data[6:]]
    records = []
    cursor = 0
    while cursor + 6 <= len(data) and data[cursor + 2:cursor + 4] == b"\x12\xa0":
        length = int.from_bytes(data[cursor:cursor + 2], "big")
        if length < 6 or cursor + length > len(data):
            break
        records.append(data[cursor + 6:cursor + length])
        cursor += length
    return records or [data]


def decode_tn5250(data: bytes) -> dict:
    screen = Screen()
    snapshots = []
    notes = []
    commands = []
    found = False
    for record in _records(data):
        index = 0
        while index < len(record):
            if record[index] != ESCAPE:
                index += 1
                continue
            if index + 1 >= len(record):
                screen.partial = True
                break
            command = record[index + 1]
            index += 2
            found = True
            if command in CLEAR_COMMANDS:
                screen.clear()
                commands.append(CLEAR_COMMANDS[command])
                snapshots.append(screen.snapshot())
            elif command == WRITE_TO_DISPLAY:
                if index + 2 > len(record):
                    screen.partial = True
                    break
                index += 2
                commands.append("write_to_display")
                index = screen.orders(record, index)
                snapshots.append(screen.snapshot())
                if screen.partial:
                    break
            else:
                screen.partial = True
                notes.append(f"5250 command 0x{command:02x} is not reconstructed")
                snapshots.append(screen.snapshot())
                break
        if screen.partial:
            break
    if not found:
        notes.append("5250 orders were not found")
    if screen.partial:
        notes.append("5250 stream is partial")
    return {"messages": [{"type": "tn5250_command", "commands": commands, "length": len(data)}],
            "screens": snapshots, "notes": notes, "coverage": CAPABILITY}
