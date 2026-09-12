import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional
from struct import pack
import argparse
import codecs

RULES: Dict[str, Dict[str, str]] = {

    
    "ret_strict": {
        "include": r": ret",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "reset_eax_strict": {
        "include": r": xor eax, eax ; ret  ;",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "neg_x_strict": {
        "include": r": neg e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "dec_x_strict": {
        "include": r": dec e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "inc_x_strict": {
        "include": r": inc e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "pop_x_strict": {
        "include": r": pop e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "add_x_strict": {
        "include": r": add e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push"#add imm
    },
    "sub_x_strict": {
        "include": r": sub e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push"#sub imm
    },
    "deref_x_strict": {
        "include": r": mov e.*?, dword",
        "exclude": r"int3|jmp|call|leave|add esp|push"#adjusted
    },
    "overwrite_x_strict": {
        "include": r": mov dword \[e+[a-zA-Z0-9].*?\], e",
        "exclude": r"int3|jmp|call|leave|add esp|push"#adjusted
    },
    "xchg_x_strict": {
        "include": r": xchg e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "mov_x_strict": {
        "include": r": mov e.*?",
        "exclude": r"int3|jmp|call|leave|add esp|\[|push|, 0x"
    },
    "push_pop_x_strict": {
        "include": r": push e.*?pop",
        "exclude": r"int3|jmp|call|leave|add esp|\["#adjusted
    },
    "lea_x_strict": {
        "include": r": lea e.*?",
        "exclude": r"int3|jmp|call|leave|add esp"#adjusted
    },
    "push_x_strict": {
        "include": r": push e+[a-zA-Z0-9].*?; ret",
        "exclude": r"int3|jmp|call|leave|add esp|\[|, 0x"
    },
    "stack_exchange_strict": {
        "include": r": xchg e+[a-zA-Z0-9].*?esp",
        "exclude": r"int3|jmp|call|leave"
    },
    "custom_query": {
        "include": r"mov e.*?, dword",
        "exclude": r"int3|jmp|call|leave"#adjusted
    }

    
}

QUERY_CATEGORIES = [
    
    # STRICT RET
    ("RET", "ret_strict"),

    # RESET EAX STRICT
    ("XOR EAX, EAX", "reset_eax_strict"),

    # STRICT NEG X
    ("NEG X", "neg_x_strict"),

    # STRICT POP X
    ("POP X", "pop_x_strict"),

    # STRICT DEC X
    ("DEC X", "dec_x_strict"),
    
    # STRICT INC X
    ("INC X", "inc_x_strict"),

    # STRICT ADD X
    ("ADD X", "add_x_strict"),

    # STRICT SUB X
    ("SUB X", "sub_x_strict"),

    # STRICT DEREFERENCE X
    ("DEREFERENCE X", "deref_x_strict"),

    # STRICT OVERWRITE X
    ("OVERWRITE X", "overwrite_x_strict"),

    # STRICT XCHG X
    ("XCHG X", "xchg_x_strict"),

    # STRICT MOV X
    ("MOV X", "mov_x_strict"),

    # STRICT PUSH POP X
    ("PUSH / POP X", "push_pop_x_strict"),

    # LEA X
    ("LEA X", "lea_x_strict"),

    # PUSH X
    ("PUSH X", "push_x_strict"),

    # STACK X
    ("STACK EXCHANGE", "stack_exchange_strict"),

    # CUSTOM
    #("CUSTOM QUERY", "custom_query")
]


def ingest_data(file_path: str) -> List[str]:
    content = Path(file_path).read_text(encoding="utf-8").strip()

    pattern = re.compile(
        r"^[ \t]*A total of[ \t]+(\d+)[ \t]+gadgets found\.[ \t]*$",
        re.MULTILINE,
    )

    match = pattern.search(content)

    if match is None:
        raise ValueError("Gadget count line was not found.")

    count_before = int(match.group(1))

    processed_content = content[match.end():]
    processed_content = processed_content.removeprefix("\r\n")
    processed_content = processed_content.removeprefix("\n")

    print(f"Original ROP Gadgets Found: {count_before}")

    return count_before, processed_content

def remove_duplicate_matches(matches):
    seen_strings = set()
    unique_matches = []

    for match in matches:
        _, separator, text = match.partition(": ")

        if not separator or text not in seen_strings:
            unique_matches.append(match)
            if separator:
                seen_strings.add(text)
    return unique_matches

def search_lines(
    lines: Iterable[str],
    include_pattern: str,
    exclude_pattern: str,
    flags: int = re.IGNORECASE,
) -> List[str]:
    include_re = re.compile(include_pattern, flags)
    exclude_re = re.compile(exclude_pattern, flags)

    matches = []
    for line in lines:
        if not include_re.search(line):
            continue
        if exclude_re and exclude_re.search(line):
            continue
        #
        addr = extract32(line)
        if checkBad(addr):
            matches.append(line)
        else:
            continue
    matches = remove_duplicate_matches(matches)
    return matches

def extract32(line: str) -> Optional[str]:
    match = re.match(r"\s*(0x[0-9A-Fa-f]{8})\b", line)
    if match:
        addr = match.group(1)
        addr = addr[2:]
        addr = int(addr, 16)
        return addr
    else:
        return None


def checkBad(address):
    global BADCHARS
    packed = pack("<L", address)  # pack the address into 4 bytes (little-endian)
    for b in packed:
        if bytes([b]) in BADCHARS:
            return False
    return True

def count_sanitized_gadgets(output_path: Path) -> int:
    count_new = 0

    with output_path.open("r", encoding="utf-8") as output_file:
        for line in output_file:
            if line.startswith("0x"):
                count_new += 1

    return count_new

def output_results(
    output_file,
    category_name: str,
    results: List[str],
) -> None:
    output_file.write(f"{category_name}: {len(results)} result(s)\n")
    output_file.write("-" * 160 + "\n")

    for line in results:
        addr = extract32(line)
        if checkBad(addr):
            output_file.write(f"{line}\n")

    output_file.write("-" * 160 + "\n\n")


def get_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-f",
        "--file",
        dest="source_file",
        required=True,
        help="Input file path",
    )

    parser.add_argument(
        "-b",
        "--badchars",
        dest="badchars",
        required=False,
        help=r"Bad characters, for example: \x00\x0a\x0d",
    )

    args = parser.parse_args()

    if args.badchars is None:
        return args.source_file, b""

    try:
        badchars = codecs.decode(
            args.badchars,
            "unicode_escape",
        ).encode("latin-1")
    except UnicodeDecodeError as error:
        parser.error(f"Invalid bad-character format: {error}")

    return args.source_file, badchars
def main():
    global BADCHARS

    source_file, BADCHARS = get_arguments()

    if not BADCHARS:
        print("[!] Failure Condition: Bad Characters Not Set")
        print("[!] Script will continue without Bad Character Filtering\n")


    input_name = Path(source_file).stem
    output_path = Path(f"out-{input_name}.txt")

    lines = ingest_data(source_file)[1].splitlines()

    with output_path.open("w", encoding="utf-8") as output_file:
        for category_name, rule_key in QUERY_CATEGORIES:
            rule = RULES[rule_key]
            results = search_lines(
                lines,
                rule["include"],
                rule["exclude"],
            )
            output_results(output_file, category_name, results)

    count_new = count_sanitized_gadgets(output_path)

    print(f"Usable Unique ROP Gadgets: {count_new}")
    print(f"\n[+] Results saved to: {output_path}")
    
if __name__ == "__main__":
    main()
