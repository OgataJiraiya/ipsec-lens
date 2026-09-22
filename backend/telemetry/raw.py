"""Parsers for locally verified strongSwan 6.0.7 / iproute2 raw output.
Key material is discarded. XFRM outbound sequence state is not receiver replay policy.
The extended replay context may exist WITHOUT the ESN flag; never infer ESN from its name.
"""
import re
from typing import Any
from ipaddress import ip_address
from backend.core.config import MAX_TELEMETRY
from backend.telemetry.importer import TelemetrySA

DH = {"MODP_2048":14,"MODP_1024":2,"ECP_256":19,"ECP_384":20,"CURVE_25519":31}
ENCRYPTION = {"AES_GCM_16":"AES-GCM-16","AES_GCM_12":"AES-GCM-12","AES_GCM_8":"AES-GCM-8",
              "AES_CBC":"AES-CBC","AES_CTR":"AES-CTR","3DES":"3DES","CHACHA20_POLY1305":"CHACHA20-POLY1305"}
INTEGRITY = {"HMAC_SHA1_96":"HMAC-SHA1-96","HMAC_SHA2_256_128":"HMAC-SHA2-256-128",
             "HMAC_SHA2_384_192":"HMAC-SHA2-384-192","HMAC_SHA2_512_256":"HMAC-SHA2-512-256"}


def bounded(text):
    if len(text.encode()) > MAX_TELEMETRY:
        raise ValueError("Telemetry exceeds limit")
    return text


def raw_events(text: str, event: str) -> list[dict]:
    bounded(text)
    result = []
    for match in re.finditer(re.escape(event)+r" event \{", text):
        # Parse one balanced event, bounded depth/tokens. Unknown fields are retained as text.
        end, depth = match.end(), 1
        while end < len(text) and depth:
            depth += (text[end] == "{") - (text[end] == "}")
            end += 1
        if depth:
            raise ValueError("Unclosed telemetry event")
        tokens = re.findall(r"[^{}\[\]=\s]+|[{}\[\]=]", text[match.end():end])
        pos = 0
        def section(depth=0):
            nonlocal pos
            if depth > 16:
                raise ValueError("Telemetry nesting limit")
            obj: dict[str, Any] = {}
            while pos < len(tokens):
                name = tokens[pos]
                pos += 1
                if name == "}":
                    return obj
                if pos >= len(tokens):
                    raise ValueError("Incomplete telemetry section")
                symbol = tokens[pos]
                pos += 1
                if symbol == "{":
                    value = section(depth+1)
                elif symbol == "=":
                    values = []
                    if pos < len(tokens) and tokens[pos] == "[":
                        pos += 1
                        while pos < len(tokens) and tokens[pos] != "]":
                            values.append(tokens[pos])
                            pos += 1
                        if pos == len(tokens):
                            raise ValueError("Incomplete telemetry list")
                        pos += 1
                    else:
                        while pos < len(tokens) and tokens[pos] != "}":
                            if pos+1 < len(tokens) and tokens[pos+1] in ("=", "{"):
                                break
                            values.append(tokens[pos])
                            pos += 1
                    value = " ".join(values)
                else:
                    raise ValueError("Unsupported raw telemetry grammar")
                if name in obj or len(obj) >= 4096:
                    raise ValueError("Duplicate/excessive telemetry fields")
                obj[name] = value
            raise ValueError("Unclosed telemetry section")
        result.append(section())
        if len(result)>4096:
            raise ValueError("Telemetry event limit")
    return result


def mapping(value):
    if not isinstance(value, dict):
        raise ValueError("Telemetry section must be a mapping")
    return value


def parse_swanctl(sas_text: str, conns_text: str = "") -> list[TelemetrySA]:
    connections = {}
    for event in raw_events(conns_text, "list-conn"):
        connections.update(event)
    output = []
    for event in raw_events(sas_text, "list-sa"):
        for name, ike in event.items():
            if not isinstance(ike, dict) or ike.get("state") != "ESTABLISHED":
                continue
            local, remote = str(ip_address(ike.get("local-host", ""))), str(ip_address(ike.get("remote-host", "")))
            for child in mapping(ike.get("child-sas", {})).values():
                child = mapping(child)
                if child.get("state") != "INSTALLED" or child.get("protocol") != "ESP":
                    continue
                props = {"mode":child.get("mode"),"encryption_algorithm":ENCRYPTION.get(child.get("encr-alg")),
                         "encryption_key_bits":int(child["encr-keysize"]) if child.get("encr-keysize") else None,
                         "integrity_algorithm":INTEGRITY.get(child.get("integ-alg")),
                         "dh_group":DH.get(child.get("dh-group"))}
                if props["encryption_algorithm"] and ("GCM" in props["encryption_algorithm"] or "POLY1305" in props["encryption_algorithm"]):
                    props["integrity_algorithm"] = "NONE"
                # life-time is remaining time, NOT configured hard lifetime: leave it UNKNOWN here.
                config = mapping(mapping(mapping(connections.get(name, {})).get("children", {})).get(child.get("name"), {}))
                proposals = [mapping(p) for p in mapping(config.get("esp_proposals", {})).values()]
                if proposals:
                    groups = [p.get("ke", "").split() for p in proposals]
                    if all(group and all(token != "NONE" for token in group) for group in groups):
                        props["pfs_enabled"] = True
                    elif all(not group or all(token == "NONE" for token in group) for group in groups):
                        props["pfs_enabled"] = False

                for incoming in (True, False):
                    spi = child.get("spi-in" if incoming else "spi-out")
                    if not spi:
                        continue
                    selectors = ((child.get("remote-ts","")+" -> "+child.get("local-ts","")) if incoming else
                                 (child.get("local-ts","")+" -> "+child.get("remote-ts","")))
                    output.append(TelemetrySA(source=remote if incoming else local,
                        destination=local if incoming else remote,spi="0x"+spi,selectors=selectors,
                        ike_association_reference=ike.get("initiator-spi","")+":"+ike.get("responder-spi",""),**props))
    return output


def parse_xfrm_state(text: str) -> list[tuple[TelemetrySA, str | None]]:
    bounded(text)
    output = []
    for block in re.split(r"(?m)(?=^src )", text):
        head = re.search(r"^src (\S+) dst (\S+)", block)
        proto = re.search(r"\bproto (esp|ah) spi (0x[0-9a-fA-F]+)(?:\(\d+\))?.*? mode (tunnel|transport)\b",block)
        if not head or not proto:
            continue
        direction_match = re.search(r"(?m)^\s*dir (in|out)\s*$",block)
        direction = direction_match[1] if direction_match else None
        fields: dict[str, Any] = {"mode":proto[3].upper()}
        flag = re.search(r"(?m)^\s*replay-window .*? flag ([^\n]+)",block)
        if flag:
            fields["esn"] = bool(re.search(r"\besn\b",flag[1]))
        # Only inbound state verifies receiver anti-replay; outbound window zero is not disabled protection.
        if direction == "in":
            extended = re.search(r"\breplay_window (\d+), bitmap-length",block)
            legacy = re.search(r"(?m)^\s*replay-window (\d+) seq",block)
            window = extended or legacy
            if window is not None:
                fields["replay_window"] = int(window[1])
        lifetime = re.search(r"expire add: soft \S+\(sec\), hard (\d+)\(sec\)",block)
        if lifetime:
            fields["configured_lifetime"] = int(lifetime[1])
        for line in block.splitlines():
            alg = re.match(r"\s*(aead|enc|auth-trunc|auth) (\S+) (\S+)(?: \((\d+) bits\))?(?: (\d+))?\s*$",line)
            if not alg:
                continue
            kind, name, key, bits_text, tag = alg.groups()
            bits = int(bits_text) if bits_text else len(key[2:])*4 if re.fullmatch(r"0x[0-9a-fA-F]+",key) else None
            if kind=="aead" and name=="rfc4106(gcm(aes))" and tag in ("64","96","128"):
                fields["encryption_algorithm"] = {"64":"AES-GCM-8","96":"AES-GCM-12","128":"AES-GCM-16"}[tag]
                fields["encryption_key_bits"] = bits-32 if bits is not None else None  # RFC4106 salt is 32 bits.
                fields["integrity_algorithm"] = "NONE"
            elif kind=="enc":
                fields["encryption_algorithm"] = {"cbc(aes)":"AES-CBC","rfc3686(ctr(aes))":"AES-CTR","cbc(des3_ede)":"3DES"}.get(name)
                fields["encryption_key_bits"] = bits-32 if name=="rfc3686(ctr(aes))" and bits else bits
            elif kind in ("auth","auth-trunc"):
                fields["integrity_algorithm"] = {("hmac(sha1)","96"):"HMAC-SHA1-96",
                    ("hmac(sha256)","128"):"HMAC-SHA2-256-128",("hmac(sha384)","192"):"HMAC-SHA2-384-192",
                    ("hmac(sha512)","256"):"HMAC-SHA2-512-256"}.get((name,tag))
        output.append((TelemetrySA.model_validate({"source":head[1],"destination":head[2],"spi":proto[2],
                                  "protocol":proto[1].upper(),**fields}),direction))
    return output


def parse_xfrm_policy(text: str) -> list[dict[str,str]]:
    bounded(text)
    rows = []
    for block in re.split(r"(?m)(?=^src )",text):
        selectors = re.search(r"^src (\S+) dst (\S+)",block)
        template = re.search(r"tmpl src (\S+) dst (\S+)\s+proto (esp|ah)(?: spi (0x[0-9a-fA-F]+))? reqid \d+ mode (tunnel|transport)",block)
        direction = re.search(r"\bdir (in|out|fwd)\b",block)
        if selectors and template and direction:
            rows.append({"source":template[1],"destination":template[2],"protocol":template[3].upper(),
                         "spi":template[4] or "","mode":template[5].upper(),"direction":direction[1],
                         "selectors":selectors[1]+" -> "+selectors[2]})
    return rows


def merge_endpoint_records(swan: list[TelemetrySA], states: list[tuple[TelemetrySA,str | None]]) -> list[TelemetrySA]:
    """Fail on conflicting claims; do not silently replace strongSwan with XFRM or vice versa."""
    records = {}
    for item in [*swan, *(s for s, _ in states)]:
        key=(item.source,item.destination,item.protocol,int(item.spi,16))
        fields=item.model_dump(exclude_none=True)
        if key not in records:
            records[key]=fields
            continue
        for name,value in fields.items():
            if name=="spi":
                continue
            if name in records[key] and records[key][name]!=value:
                raise ValueError(f"Conflicting endpoint evidence for {name}")
            records[key][name]=value
    return [TelemetrySA.model_validate(value) for value in records.values()]
