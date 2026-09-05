#!/usr/bin/env python3

"""Makes NSwag's output idiomatic C#, deterministically.

NSwag has no property-name hook on its command line: NJsonSchema camel-cases
dashes but leaves underscores alone, so a wire name like `is_vpn` becomes the
property `Is_vpn`. That is not a C# name, and most of these DTOs are public
API, so the whole surface would ship reading like the JSON. Everything below is
mechanical, derived from the generated file itself rather than from a list of
names someone has to keep in step with the spec, and every change is printed.

Same idea as the Python SDK normalizing the generator's em-dashes: run from
scripts/generate.sh, right after generating, so regeneration stays byte-stable.
"""

import re
import sys

# Types that exist only to carry the wire: the client throws them, unwraps
# them, or takes them as a parameter. None of them belongs in the public API,
# and one of them (Error) would be a genuinely bad public name.
INTERNAL_TYPES = [
    "WireException",
    "LookupError",
    "Error",
    "Response",
    "Response2",
    "Response3",
]

# The spec's one csvgz/mmdb enum is reached from five places, and an inline enum
# gets a name per place, so the generator emits five copies of it. They are
# folded into the single DatasetFormat a caller passes to the Database methods
# and reads back off LicensedVersion.Formats[].Format.
TYPE_RENAMES = {
    "DatasetFormatSizeFormat": "DatasetFormat",
    "Format": "DatasetFormat",
    "Format2": "DatasetFormat",
    "SampleFormats": "DatasetFormat",
    "Checksums": "DatasetChecksums",
    "LicensedDatasetLicenseType": "DatasetLicenseType",
}

# NSwag 14.6 tags enum members with JsonStringEnumMemberName, which only exists from .NET 9, while
# its OWN query-string serializer reads EnumMemberAttribute. Left alone the client does not compile
# on net8.0 and, where it does compile, sends `?format=1` instead of `?format=mmdb`.
#
# Only the QUERY direction needs this. Reads are covered by the per-property
# JsonConverter(JsonStringEnumConverter<T>) NSwag also emits, which matches the C# member name
# case-insensitively; measured by deleting a client-wide converter and watching nothing fail.
ENUM_MEMBER = re.compile(
    r'(?P<indent>[ \t]*)\[System\.Text\.Json\.Serialization\.JsonStringEnumMemberName\(@"(?P<wire>[^"]*)"\)\]\n'
    r"(?P<next>[ \t]*)(?P<member>[A-Za-z_][A-Za-z0-9_]*) = "
)

ENUM_BLOCK = re.compile(
    r"\n[ \t]*\[System\.CodeDom[^\n]*\]\n[ \t]*public enum DatasetFormat\n[ \t]*\{.*?\n[ \t]*\}\n",
    re.DOTALL,
)

PROPERTY = re.compile(
    r'(\[System\.Text\.Json\.Serialization\.JsonPropertyName\("(?P<wire>[^"]+)"\)\]\n'
    # An enum property carries a second attribute between the two, and skipping it silently left
    # DatasetFormatSize.Format named after its own type. A LIST of enums carries a comment there
    # instead of an attribute, and skipping that left sampleFormats named DatasetFormat.
    r"(?:[ \t]*(?:\[|//)[^\n]*\n)*"
    r"\s*public\s+[^\n]*?\s)(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?=\s*\{ get; set; \})"
)

# NSwag writes a per-property converter for a scalar enum and this comment for an enum inside a
# LIST, where System.Text.Json's default is to read a NUMBER. Wire.cs registers a converter for
# DatasetFormat to cover it, so a list of any OTHER enum would deserialize no healthy answer.
ITEM_CONVERTER_TODO = re.compile(
    r"// TODO\(system\.text\.json\): Add string enum item converter\n"
    r"[ \t]*public [^\n]*?IReadOnlyList<(?P<item>[A-Za-z_][A-Za-z0-9_]*)>"
)


def main() -> int:
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        src = f.read()

    # Types first: renaming Checksums also hits the property of that name, and the
    # property pass then puts it back from the wire name it carries.
    src, retyped = rename_types(src)
    src, folded = fold_duplicate_format_enums(src)
    src, renamed = pascal_case_properties(src)
    src, hidden = hide_wire_types(src)
    src, members = fix_enum_member_names(src)

    with open(path, "w", encoding="utf-8") as f:
        f.write(src)

    for old, new in renamed:
        print(f"  property {old} -> {new}")
    for old, new in retyped:
        print(f"  type     {old} -> {new}")
    for name in hidden:
        print(f"  internal {name}")
    print(f"  {len(renamed)} properties, {len(retyped)} types renamed, "
          f"{folded} duplicate enums folded, {len(hidden)} hidden, {members} enum members retagged")

    return check(src)


def pascal_case_properties(src):
    """Renames every property to the PascalCase of the wire name above it.

    Derived from the JsonPropertyName attribute rather than from the C# name,
    so the result is the name the API actually serves and a generator that
    starts mangling names differently cannot quietly satisfy this.
    """
    renamed = []

    def fix(m):
        want = "".join(part[:1].upper() + part[1:] for part in m.group("wire").split("_"))
        have = m.group("name")
        if want == have:
            return m.group(0)
        renamed.append((have, want))
        return m.group(1) + want

    return PROPERTY.sub(fix, src), renamed


def rename_types(src):
    retyped = []
    # Doc comments are the spec's own prose, where these words are English rather
    # than identifiers, so they are left exactly as the API describes itself.
    lines = src.split("\n")
    for old, new in TYPE_RENAMES.items():
        hit = False
        for i, line in enumerate(lines):
            if line.lstrip().startswith("///"):
                continue
            lines[i], n = re.subn(rf"(?<![\w.]){re.escape(old)}(?![\w])", new, line)
            hit = hit or n > 0
        if hit:
            retyped.append((old, new))
    return "\n".join(lines), retyped


def fold_duplicate_format_enums(src):
    """Keeps one DatasetFormat declaration out of the renamed copies.

    They must be textually identical: the same spec enum reached four ways
    cannot legitimately differ, so a difference means the spec grew a variant
    this fold would silently discard.
    """
    blocks = ENUM_BLOCK.findall(src)
    if len(blocks) < 2:
        return src, 0
    if len(set(blocks)) != 1:
        raise SystemExit("DatasetFormat copies differ; the spec's format enums are no longer the same")
    seen = 0

    def keep_first(m):
        nonlocal seen
        seen += 1
        return m.group(0) if seen == 1 else "\n"

    return ENUM_BLOCK.sub(keep_first, src), len(blocks) - 1


def fix_enum_member_names(src):
    """Retags enum members with the attribute NSwag's own query serializer reads.

    Also asserts that each wire value is the camelCase of its C# member name, which is what the
    READ side needs: NSwag's per-property converter matches on member names. Every value in this
    spec is one lowercase word, so the two coincide; a spec that grew a multi-word value would
    break reads silently, so it fails here loudly instead.
    """
    mismatched = []

    def retag(m):
        wire, member = m.group("wire"), m.group("member")
        if wire != member[:1].lower() + member[1:]:
            mismatched.append(f"{member} serializes as {wire!r}, which camelCase would not produce")
        return (f'{m.group("indent")}[System.Runtime.Serialization.EnumMember(Value = @"{wire}")]\n'
                f'{m.group("next")}{member} = ')

    src, n = ENUM_MEMBER.subn(retag, src)
    if mismatched:
        raise SystemExit("enum wire values no longer match their member names:\n  " + "\n  ".join(mismatched))
    return src, n


def hide_wire_types(src):
    """Demotes the wire-only types to internal.

    NSwag applies one access modifier to every DTO it emits, so the envelopes,
    the two error bodies and the duplicate format enums come out public
    alongside the models a caller genuinely reads.
    """
    hidden = []
    for name in INTERNAL_TYPES:
        pattern = rf"^(\s*)public (partial class|enum) {re.escape(name)}(?=[\s<:])"
        src, n = re.subn(pattern, r"\1internal \2 " + name, src, flags=re.MULTILINE)
        if n:
            hidden.append(name)
    return src, hidden


def check(src) -> int:
    """Refuses to leave behind the two defects this script exists to remove."""
    bad = []
    for m in PROPERTY.finditer(src):
        want = "".join(part[:1].upper() + part[1:] for part in m.group("wire").split("_"))
        if m.group("name") != want:
            bad.append(f"property {m.group('name')} should be {want}, from the wire name")
    for m in re.finditer(r"^\s*public (?:partial class|enum) (Response\d?|Error|Format\d?)\b", src, re.M):
        bad.append(f"wire type {m.group(1)} is still public")
    for m in ITEM_CONVERTER_TODO.finditer(src):
        if m.group("item") != "DatasetFormat":
            bad.append(f"a list of {m.group('item')} has no item converter; only DatasetFormat has one")
    for line in bad:
        print(f"NORMALIZE FAILED: {line}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
