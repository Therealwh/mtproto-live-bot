#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Настоящая проверка MTProto-прокси (не просто открытый порт).

ee (FakeTLS): клиент шлёт TLS ClientHello (SNI = домен из секрета, client random
= HMAC-SHA256(ключ секрета, hello с нулевым random) XOR метка времени), читает
ServerHello+CCS+AppData и верифицирует HMAC ответа сервера (ровно как клиент
Telegram Android в ConnectionSocket.cpp), затем внутри TLS поднимает
obfuscated2-поток (secure-тег DD, AES-CTR с ключом = 16 байт секрета) и
прогоняет MTProto-хендшейк req_pq -> resPQ.
dd (secure) и классика (16 байт): тот же obfuscated2 + req_pq -> resPQ без TLS.

Прокси признаётся живым только если вернулся resPQ с нашим nonce — то есть
сервер реально ретранслирует MTProto в Telegram DC, а не просто держит порт.

Референсы протокола:
- alexbers/mtprotoproxy — серверная валидация (DIGEST_POS=11, DIGEST_LEN=32,
  HMAC-XOR дайджест, ожидание "16 03 01" + длина >= 512);
- Telethon v1.36 tcpmtproxy.py — клиентский obfuscated2-хендшейк;
- 9seconds/mtg v2 — формат ee-секрета [0xEE][16-байт ключ][домен];
- Telegram Android TLSHello.cpp / ConnectionSocket.cpp — канонический клиент:
  структура ClientHello (517 байт с padding), проверка ServerHello HMAC,
  CCS + obfuscated2 в AppData (0x17) блоками <= 2878 байт.

CLI:  python mtproto_check.py "tg://proxy?server=...&port=...&secret=..."
      python mtproto_check.py --selftest
"""
import base64
import hashlib
import hmac
import os
import socket
import struct
import time

# ---------------------------------------------------------------- AES-128-CTR
# Чистый python: трафика мало (64-байт заголовок + req_pq/resPQ), скорости хватает.

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a = (a ^ 0x1B) & 0xFF
    return a


def _expand_key(key):
    """AES key schedule (128/256 бит) -> список round keys. Ключи MTProto-obfuscated2 —
    это sha256 (32 байта = AES-256), поэтому AES-128 недостаточно."""
    nk = len(key) // 4
    rounds = nk + 6  # 10 для AES-128, 14 для AES-256
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            t[0] ^= _RCON[i // nk - 1]
        elif nk == 8 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [bytes(w[4 * r]) + bytes(w[4 * r + 1]) + bytes(w[4 * r + 2]) + bytes(w[4 * r + 3])
            for r in range(rounds + 1)]


def _enc_block(rk, block):
    s = [a ^ b for a, b in zip(block, rk[0])]
    for rnd in range(1, len(rk) - 1):
        s = [_SBOX[b] for b in s]
        for r in range(1, 4):  # ShiftRows
            row = [s[4 * c + r] for c in range(4)]
            for c in range(4):
                s[4 * c + r] = row[(c + r) % 4]
        for i in range(4):     # MixColumns
            c = s[4 * i:4 * i + 4]
            t = c[0] ^ c[1] ^ c[2] ^ c[3]
            u = c[0]
            c[0] ^= t ^ _xtime(c[0] ^ c[1])
            c[1] ^= t ^ _xtime(c[1] ^ c[2])
            c[2] ^= t ^ _xtime(c[2] ^ c[3])
            c[3] ^= t ^ _xtime(c[3] ^ u)
            s[4 * i:4 * i + 4] = c
        s = [a ^ b for a, b in zip(s, rk[rnd])]
    s = [_SBOX[b] for b in s]
    for r in range(1, 4):
        row = [s[4 * c + r] for c in range(4)]
        for c in range(4):
            s[4 * c + r] = row[(c + r) % 4]
    return bytes(a ^ b for a, b in zip(s, rk[-1]))


class AesCtr:
    """AES-128-CTR поток: update() можно вызывать кусками любого размера."""

    def __init__(self, key, iv16):
        self.rk = _expand_key(key)
        self.ctr = int.from_bytes(iv16, "big")

    def update(self, data):
        out = bytearray()
        pos, n = 0, len(data)
        while pos < n:
            ks = _enc_block(self.rk, self.ctr.to_bytes(16, "big"))
            self.ctr = (self.ctr + 1) % (1 << 128)
            chunk = data[pos:pos + 16]
            out += bytes(a ^ b for a, b in zip(chunk, ks))
            pos += len(chunk)
        return bytes(out)


def _selftest():
    # NIST SP 800-38A F.5.1 / FIPS-197 C.1 (AES-128) и C.3 (AES-256)
    assert _enc_block(_expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f")),
                      bytes.fromhex("00112233445566778899aabbccddeeff")
                      ).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", "AES-128 FIPS-197 вектор не сошёлся"
    assert _enc_block(_expand_key(bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                                                "1f352c073b6108d72d9810a3ee14a0f1")),
                      bytes.fromhex("00112233445566778899aabbccddeeff")
                      ).hex() == "57890497aaf5361019273fc7936b4a49", "AES-256 FIPS-197 вектор не сошёлся"
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert _enc_block(_expand_key(key),
                      bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
                      ).hex() == "3ad77bb40d7a3660a89ecaf32466ef97", "AES SP800-38A вектор не сошёлся"
    ctr = AesCtr(key, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
    ct = ctr.update(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")) + \
        ctr.update(bytes.fromhex("ae2d8a571e03ac9c9eb76fac45af8e51"))
    assert ct.hex() == "874d6191b620e3261bef6864990db6ce" + "9806f66b7970fdff8617187bb9fffdff", \
        "AES-CTR SP800-38A вектор не сошёлся"
    # XOR-дайджест FakeTLS: computed ^ digest == 28 нулей + время
    key16 = os.urandom(16)
    hello = bytearray(b"\x16\x03\x01\x02\x04" + os.urandom(511))
    hello[11:43] = b"\x00" * 32
    hm = hmac.new(key16, bytes(hello), hashlib.sha256).digest()
    ts = struct.pack("<i", int(time.time()))
    hello[11:43] = bytes(hm[i] ^ ts[i - 28] if i >= 28 else hm[i] for i in range(32))
    xored = bytes(d ^ c for d, c in zip(hello[11:43], hm))
    assert xored[:28] == b"\x00" * 28 and xored[28:] == ts, "FakeTLS digest не сошёлся"
    return True


# ------------------------------------------------------------- разбор секрета
def _classify_raw(raw):
    if raw[0] == 0xEE:
        # ee + ключ 16 байт + домен (как в Telegram Android: substr(1,16), substr(17))
        if len(raw) >= 18:
            return "ee", raw[1:17], raw[17:]
        return None
    if raw[0] == 0xDD and len(raw) == 17:
        return "dd", raw[1:17], b""
    if len(raw) == 16:
        return "classic", raw, b""
    return None


def parse_secret(secret):
    """-> (kind, key16, domain) | None. kind: ee (FakeTLS), dd (secure), classic (16 байт).
    Секрет может быть в hex ("ee...") или base64 (mtg v2)."""
    s = secret.strip()
    if not s:
        return None
    decoders = []
    if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        decoders.append(lambda t: bytes.fromhex(t))
    decoders.append(lambda t: base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
    for decode in decoders:
        try:
            raw = decode(s)
        except Exception:
            continue
        if raw:
            parsed = _classify_raw(raw)
            if parsed:
                return parsed
    return None


# ------------------------------------------------------------------- FakeTLS
def build_client_hello(key16, domain):
    """ClientHello-запись 517 байт (как у Chrome/Telegram): padding ext добивает
    длину записи до 517, чтобы пройти проверку alexbers (>= 512)."""
    sess = os.urandom(32)
    suites = bytes.fromhex(
        "0a0a"  # GREASE-шифр (0x?a?a)
        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")
    fixed_ext = bytes.fromhex(
        "000a00080006001d00170018"                                      # supported_groups
        "000b00020100"                                                  # ec_point_formats
        "000d00180016" "09040905090604030804040105030805050108060601"   # signature_algorithms
        "0010000e000c") + b"\x02h2\x08http/1.1" + bytes.fromhex(        # ALPN h2 + http/1.1
        "00120000"                                                      # encrypt_then_mac
        "00170000"                                                      # extended_master_secret
        "00230000"                                                      # session_ticket
        "002b00050403040303"                                            # supported_versions
        "003300260024001d0020") + os.urandom(32) + bytes.fromhex(       # key_share x25519
        "ff01000100")                                                   # renegotiation_info
    # RFC 6066: body = server_name_list_len(2) + name_type(1) + name_len(2) + name
    sni_body = struct.pack(">H", len(domain) + 3) + b"\x00" + \
        struct.pack(">H", len(domain)) + domain
    sni = b"\x00\x00" + struct.pack(">H", len(sni_body)) + sni_body
    body = b"\x03\x03" + b"\x00" * 32 + b"\x20" + sess + b"\x00\x20" + suites + b"\x01\x00"
    # запись: 5 байт заголовка + 4 байт handshake-заголовка + тело + 2 байта ext_len + ext
    ext_free = 517 - (5 + 4 + len(body) + len(fixed_ext) + len(sni) + 4 + 2)
    if ext_free > 0:
        padding = b"\x00\x15" + struct.pack(">H", ext_free) + b"\x00" * ext_free
    else:
        padding = b""
    exts = sni + fixed_ext + padding
    body += struct.pack(">H", len(exts)) + exts
    hello = bytearray(b"\x16\x03\x01" + struct.pack(">H", len(body) + 4) +
                      b"\x01" + struct.pack(">I", len(body))[1:] + body)
    # client random = HMAC(ключ секрета, hello с нулевым random) XOR (нули + время LE)
    hm = hmac.new(key16, bytes(hello[:11]) + b"\x00" * 32 + bytes(hello[43:]),
                  hashlib.sha256).digest()
    ts = struct.pack("<i", int(time.time()))
    hello[11:43] = bytes(hm[i] ^ ts[i - 28] if i >= 28 else hm[i] for i in range(32))
    return bytes(hello), sess


class TlsSock:
    """TCP + запись/чтение TLS-records (структурные, без реального TLS-стека)."""

    def __init__(self, sock):
        self.sock = sock

    def sendall(self, data):
        self.sock.sendall(data)

    def send_records(self, *records):
        self.sock.sendall(b"".join(records))

    @staticmethod
    def record(rtype, payload):
        return bytes([rtype]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload

    def recv_record(self):
        hdr = self._recv_exact(5)
        if hdr[0] not in (0x14, 0x16, 0x17):
            raise ValueError("неожиданный тип TLS-записи 0x%02x" % hdr[0])
        if hdr[1:3] != b"\x03\x03":
            raise ValueError("неожиданная версия TLS-записи %s" % hdr[1:3].hex())
        return hdr[0], self._recv_exact(int.from_bytes(hdr[3:5], "big"))

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(min(65536, n - len(buf)))
            if not chunk:
                raise ConnectionError("соединение закрыто (получено %d из %d)" % (len(buf), n))
            buf += chunk
        return buf

    def recv_plain(self, n):
        """Читает n байт как есть (для ответа ServerHello: тип записи невалидируем заранее)."""
        return self._recv_exact(n)


def faketls_handshake(sock, key16, domain):
    """FakeTLS-хендшейк: ClientHello с SNI=домен, верификация ServerHello HMAC'ом
    (полностью повторяет проверку клиента Telegram Android, proxyAuthState==11)."""
    hello, sess = build_client_hello(key16, domain)
    sock.sendall(hello)
    # ответ: [0x16 ServerHello][0x14 CCS][0x17 шум] — строго в этой последовательности
    buf = bytearray(sock.recv_plain(16))
    if buf[:3] != b"\x16\x03\x03":
        raise ValueError("ответ не начинается с 16 03 03: %s" % bytes(buf[:8]).hex())
    len1 = int.from_bytes(buf[3:5], "big")
    if len1 < 100:
        raise ValueError("подозрительно короткий ServerHello (%d байт)" % len1)
    while len(buf) < 5 + len1 + 11:
        buf += sock.recv_plain(5 + len1 + 11 - len(buf))
    if bytes(buf[5 + len1:5 + len1 + 9]) != b"\x14\x03\x03\x00\x01\x01\x17\x03\x03":
        raise ValueError("за ServerHello нет ChangeCipherSpec+AppData (это не MTProto FakeTLS)")
    len2 = int.from_bytes(buf[5 + len1 + 9:5 + len1 + 11], "big")
    while len(buf) < 5 + len1 + 11 + len2:
        buf += sock.recv_plain(5 + len1 + 11 + len2 - len(buf))
    resp = bytes(buf)
    # HMAC(ключ, наш client random + ответ с нулевым ServerHello-random) == дайджест в ответе
    server_digest = resp[11:43]
    zeroed = resp[:11] + b"\x00" * 32 + resp[43:]
    expected = hmac.new(key16, hello[11:43] + zeroed, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, server_digest):
        raise ValueError("ServerHello digest не совпал — сервер не знает ключ секрета")
    return sess


# ----------------------------------------------------------------- obfuscated2
_BAD_TAGS = (b"PVrG", b"GET ", b"POST", b"HEAD", b"OPTI", b"\xee\xee\xee\xee",
             b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02")


def obfuscated2(key16, tag, dc=2):
    """64-байтный obfuscated2-заголовок + пара CTR-потоков (Telethon MTProxyIO.init_header).
    tag: b"\xdd\xdd\xdd\xdd" (secure/padded) или b"\xee\xee\xee\xee" (intermediate)."""
    while True:
        r = bytearray(os.urandom(64))
        if r[0] == 0xEF or bytes(r[:4]) in _BAD_TAGS or r[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    enc_key = hashlib.sha256(bytes(r[8:40]) + key16).digest()
    enc_iv = bytes(r[40:56])
    rev = bytes(r[55:7:-1])
    dec_key = hashlib.sha256(rev[:32] + key16).digest()
    dec_iv = rev[32:48]
    enc, dec = AesCtr(enc_key, enc_iv), AesCtr(dec_key, dec_iv)
    r[56:60] = tag
    r[60:62] = struct.pack("<h", dc)
    r[62:64] = os.urandom(2)
    full = bytes(r)
    header = full[:56] + enc.update(full)[56:64]  # сервер расшифровывает те же 64 байта тем же потоком
    return header, enc, dec


def make_frame(payload, padded):
    """Кадр транспорта: intermediate (len%4==0) или padded intermediate (паддинг 0..15, длина%4==0)."""
    if padded:
        pad_len = 4 * (int.from_bytes(os.urandom(1), "big") % 4)  # 0, 4, 8 или 12
        payload = payload + os.urandom(pad_len)
    return struct.pack("<I", len(payload)) + payload


class Obf2Reader:
    """Расшифровывающий читатель obfuscated2-потока поверх TLS-записей (или сырого сокета)."""

    def __init__(self, sock, dec, tls=None):
        self.sock = sock
        self.dec = dec
        self.tls = tls
        self.buf = b""

    def read(self, n):
        while len(self.buf) < n:
            if self.tls:
                rtype, payload = self.tls.recv_record()
                if rtype != 0x17:
                    raise ValueError("ожидали ApplicationData, получили 0x%02x" % rtype)
            else:
                payload = self._recv_exact_sock(65536)
            self.buf += self.dec.update(payload)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _recv_exact_sock(self, n):
        chunk = self.sock.recv(n)
        if not chunk:
            raise ConnectionError("соединение закрыто до ответа MTProto")
        return chunk


def mtproto_req_pq(nonce):
    """req_pq_multi#be7e8ef1 в unencrypted MTProto-сообщении (auth_key_id=0).
    Современные DC принимают только req_pq_multi (старый req_pq#6049974a молча
    игнорируется). msg_id обязан быть кратен 4 (требование серверов MTProto)."""
    body = struct.pack("<I", 0xBE7E8EF1) + nonce
    msg_id = int(time.time() * 2 ** 32) // 4 * 4
    msg = b"\x00" * 8 + struct.pack("<q", msg_id) + \
        struct.pack("<i", len(body)) + body
    return msg


def mtproto_check_resp(payload, nonce):
    """resPQ#05162463: наш nonce, pq 8 байт, fingerprints (boxed Vector<long>) > 0."""
    if payload[:8] != b"\x00" * 8:
        raise ValueError("auth_key_id ответа не нулевой")
    mlen = int.from_bytes(payload[16:20], "little")
    body = payload[20:20 + mlen]
    if len(body) < mlen or mlen < 56:
        raise ValueError("обрезанный resPQ (msg_len=%d)" % mlen)
    if body[:4] != struct.pack("<I", 0x05162463):
        raise ValueError("ctor не resPQ#05162463: %s" % body[:4].hex())
    if body[4:20] != nonce:
        raise ValueError("nonce в resPQ не совпал с нашим")
    if body[36] != 8:
        raise ValueError("pq не 8 байт (len=%d)" % body[36])
    pq = body[37:45]
    if body[48:52] != struct.pack("<I", 0x1CB5C415):  # TL-конструктор vector#1cb5c415
        raise ValueError("нет конструктора Vector<long>: %s" % body[48:52].hex())
    fp_count = int.from_bytes(body[52:56], "little")
    if not 1 <= fp_count <= 16:
        raise ValueError("странный count fingerprints: %d" % fp_count)
    return pq, fp_count


# --------------------------------------------------------------------- чекер
def check_proxy(server, port, secret, timeout=8, dc=2):
    """-> {"ok": bool, "ms": int|None, "check": "faketls"|"mtproto"|None,
           "stage": str, "detail": str}"""
    res = {"ok": False, "ms": None, "check": None, "stage": "", "detail": ""}
    parsed = parse_secret(secret)
    if not parsed:
        res["stage"], res["detail"] = "secret", "нераспознанный формат секрета"
        return res
    kind, key16, domain = parsed
    t0 = time.time()
    sock = None
    try:
        sock = socket.create_connection((server.strip(), port), timeout=timeout)
        sock.settimeout(timeout)
        res["stage"] = "connect"
        nonce = os.urandom(16)
        if kind == "ee":
            res["check"] = "faketls"
            res["stage"] = "client_hello"
            tls = TlsSock(sock)
            faketls_handshake(tls, key16, domain)
            res["stage"] = "server_hello"
            header, enc, dec = obfuscated2(key16, b"\xdd\xdd\xdd\xdd", dc)
            reader = Obf2Reader(sock, dec, tls=tls)
            res["stage"] = "req_pq"
            tls.send_records(TlsSock.record(0x14, b"\x01"),   # ChangeCipherSpec
                             TlsSock.record(0x17, header))     # obfuscated2 внутри AppData
            tls.send_records(TlsSock.record(0x17, enc.update(
                make_frame(mtproto_req_pq(nonce), padded=True))))
        else:
            res["check"] = "mtproto"
            header, enc, dec = obfuscated2(key16, b"\xdd\xdd\xdd\xdd" if kind == "dd" else b"\xee\xee\xee\xee", dc)
            reader = Obf2Reader(sock, dec)
            res["stage"] = "req_pq"
            sock.sendall(header)
            sock.sendall(enc.update(make_frame(mtproto_req_pq(nonce), padded=(kind == "dd"))))
        res["stage"] = "resPQ"
        while True:
            frame_len = int.from_bytes(reader.read(4), "little")
            if frame_len == 4:  # пустой padding-кадр (пинг) — пропускаем, как alexbers
                reader.read(4)
                continue
            if not 40 <= frame_len <= 16384:
                raise ValueError("странный размер кадра: %d" % frame_len)
            break
        pq, fp_count = mtproto_check_resp(reader.read(frame_len), nonce)
        res["ok"] = True
        res["detail"] = "resPQ ok (pq=%s, fingerprints=%d)" % (pq.hex()[:8] + "…", fp_count)
        res["ms"] = int((time.time() - t0) * 1000)
        return res
    except Exception as e:
        res["detail"] = "%s: %s" % (type(e).__name__, str(e)[:120])
        return res
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


# ----------------------------------------------------------------------- CLI
def _link_args(link):
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(link).query)
    return q["server"][0], int(q["port"][0]), q["secret"][0]


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
        print("selftest: AES-128-CTR и FakeTLS digest — OK")
        sys.exit(0)
    if len(sys.argv) >= 4:
        server, port, secret = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    else:
        server, port, secret = _link_args(sys.argv[1])
    parsed = parse_secret(secret)
    if not parsed:
        print("секрет не распознан:", secret)
        sys.exit(1)
    kind, key16, domain = parsed
    dom = domain.decode("latin-1", "replace") if domain else "(нет)"
    print("server=%s:%d kind=%s key=%s… domain=%r" % (server, port, kind, key16[:4].hex(), dom))
    t0 = time.time()
    r = check_proxy(server, port, secret)
    print("%-12s %s  (%.2f s)" % ("[%s]" % r["stage"], "OK — " + r["detail"] if r["ok"] else "FAIL — " + r["detail"],
                                  time.time() - t0))
    sys.exit(0 if r["ok"] else 1)
