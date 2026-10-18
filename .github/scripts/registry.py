"""Approved public SDK repositories; private/server repositories cannot opt in."""
SDK_REPOSITORIES = {'go': 'licensebox/go', 'python': 'licensebox/python', 'javascript': 'licensebox/javascript', 'c': 'licensebox/c', 'cpp': 'licensebox/cpp', 'rust': 'licensebox/rust', 'java': 'licensebox/java', 'julia': 'licensebox/julia', 'dotnet': 'licensebox/dotnet', 'swift': 'licensebox/swift', 'objc': 'licensebox/objc', 'fortran': 'licensebox/fortran', 'r': 'licensebox/r', 'matlab': 'licensebox/matlab', 'octave': 'licensebox/octave', 'wolfram': 'licensebox/wolfram', 'dart': 'licensebox/dart', 'ruby': 'licensebox/ruby', 'php': 'licensebox/php', 'zig': 'licensebox/zig', 'nim': 'licensebox/nim', 'd': 'licensebox/d', 'pascal': 'licensebox/pascal', 'haskell': 'licensebox/haskell', 'ocaml': 'licensebox/ocaml', 'beam': 'licensebox/beam', 'lua': 'licensebox/lua', 'perl': 'licensebox/perl', 'tcl': 'licensebox/tcl', 'powershell': 'licensebox/powershell', 'cobol': 'licensebox/cobol', 'cli': 'licensebox/cli', 'wasm': 'licensebox/wasm'}

def registered(contract, language):
    client = contract.get("clients", {}).get(language)
    if not client or client.get("repository") != SDK_REPOSITORIES.get(language):
        raise ValueError("SDK is not registered in the approved public contract")
    if not isinstance(client.get("native_c", False), bool):
        raise ValueError("native_c must be a boolean")
    return client
