#!/usr/bin/env python3

"""Writes the copy of the pinned spec that NSwag generates from.

spec/openapi.yaml stays the published spec byte for byte, so its diff shows a
spec version. A few of the spec's changes would move a public type, which only
a major may do, so they are taken out of the generator's copy here instead, and
each must be found exactly where it is expected or the run fails:

- Spec 2026.11.22 requires the AS's `country` and `rpki_status`, which every
  answer has served since 2026-11-20. Generated as required they would turn
  `Asn.Country` and `Asn.RpkiStatus` from `string?` into `string`, so the
  public type keeps them optional. The decoder still refuses an answer without
  them: Wire.cs's AnswerMembers names both, and HeldOptional says why.
- The same spec gives the satellite operator's `asn` `format: int64`, which
  would turn `SatelliteDetail.Asn` from `int?` into `long?`, so the public type
  keeps its width.
- The answer's `user_agent` verdict comes only when a lookup sends a
  `user_agent`, which this client does not yet, so it adds no public type
  until it does. The batch request's `user_agents` goes too: BatchLookupRequest
  is a public type, and NSwag would write the unset map as `"user_agents":null`.

The request's `user_agent` query parameter stays in: it reaches only the
internal WireClient, and the client passes null, which sends nothing.
"""

import sys

# (schema, entry): an entry dropped from a schema's `required` list.
REQUIRED_DROPPED = [
    ("Asn", "country"),
    ("Asn", "rpki_status"),
]

# (schema, property, line): a line dropped from one property's own block.
PROPERTY_LINES_DROPPED = [
    ("SatelliteDetail", "asn", "format: int64"),
]

# (schema, property): a property dropped, with everything indented under it.
PROPERTIES_DROPPED = [
    ("LookupResponse", "user_agent"),
    ("BatchLookupRequest", "user_agents"),
]

SCHEMA_INDENT = " " * 4
FIELD_INDENT = " " * 6
MEMBER_INDENT = " " * 8
ATTRIBUTE_INDENT = " " * 10


def schema_span(lines, name):
    """The [start, end) line range of components.schemas.<name>."""
    header = f"{SCHEMA_INDENT}{name}:\n"
    starts = [i for i, line in enumerate(lines) if line == header]
    if len(starts) != 1:
        raise SystemExit(f"schema {name}: expected one header, found {len(starts)}")
    start = starts[0]
    end = start + 1
    while end < len(lines) and (lines[end].strip() == "" or lines[end].startswith(SCHEMA_INDENT + " ")):
        end += 1
    return start, end


def field_span(lines, start, end, field, name):
    """The [start, end) line range of a schema's `properties:` or `required:`."""
    header = f"{FIELD_INDENT}{field}:\n"
    found = [i for i in range(start, end) if lines[i] == header]
    if len(found) != 1:
        raise SystemExit(f"schema {name}: expected one `{field}:`, found {len(found)}")
    first = found[0] + 1
    last = first
    while last < end and (lines[last].strip() == "" or lines[last].startswith(FIELD_INDENT + " ")):
        last += 1
    return first, last


def property_span(lines, schema, prop):
    """The [start, end) line range of one property, its name line included."""
    start, end = schema_span(lines, schema)
    first, last = field_span(lines, start, end, "properties", schema)
    wanted = f"{MEMBER_INDENT}{prop}:\n"
    hits = [i for i in range(first, last) if lines[i] == wanted]
    if len(hits) != 1:
        raise SystemExit(f"schema {schema}: property `{prop}` not found once; review the transform")
    stop = hits[0] + 1
    while stop < last and (lines[stop].strip() == "" or lines[stop].startswith(MEMBER_INDENT + " ")):
        stop += 1
    return hits[0], stop


def drop_required(lines, schema, entry):
    start, end = schema_span(lines, schema)
    first, last = field_span(lines, start, end, "required", schema)
    wanted = f"{MEMBER_INDENT}- {entry}\n"
    hits = [i for i in range(first, last) if lines[i] == wanted]
    if len(hits) != 1:
        raise SystemExit(f"schema {schema}: `{entry}` is no longer required once; review the transform")
    del lines[hits[0]]


def drop_property_line(lines, schema, prop, line):
    start, stop = property_span(lines, schema, prop)
    wanted = f"{ATTRIBUTE_INDENT}{line}\n"
    hits = [i for i in range(start + 1, stop) if lines[i] == wanted]
    if len(hits) != 1:
        raise SystemExit(f"schema {schema}: `{prop}` no longer has `{line}` once; review the transform")
    del lines[hits[0]]


def drop_property(lines, schema, prop):
    start, stop = property_span(lines, schema, prop)
    del lines[start:stop]


def main() -> int:
    source, target = sys.argv[1], sys.argv[2]
    with open(source, encoding="utf-8") as f:
        lines = f.readlines()
    for schema, entry in REQUIRED_DROPPED:
        drop_required(lines, schema, entry)
        print(f"  generator input: {schema}.{entry} left optional")
    for schema, prop, line in PROPERTY_LINES_DROPPED:
        drop_property_line(lines, schema, prop, line)
        print(f"  generator input: {schema}.{prop} without `{line}`")
    for schema, prop in PROPERTIES_DROPPED:
        drop_property(lines, schema, prop)
        print(f"  generator input: {schema}.{prop} left out")
    with open(target, "w", encoding="utf-8") as f:
        f.writelines(lines)
    return 0


if __name__ == "__main__":
    sys.exit(main())
