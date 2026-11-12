#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Настоящая проверка MTProto-прокси: obfuscated2 хендшейк + req_pq → resPQ.
Если через прокси приходит валидный resPQ с нашим nonce — сервер реально
ретранслирует трафик в Telegram DC, а не просто «порт открыт»."""
import os, hashlib, socket, struct, time

ABRIDGED_TAG = b"\xEF\xEF\xEF\xEF"
PREKEY_LEN, IV_LEN, SKIP_LEN = 32, 16, 8

class Obf2Client:
    """dd-режим (plain MTProto): обфускация abridged + CTR-потоки."""

    def __init__(self, secret_hex: bytes, dc_id: int = 2):
        # нормализация: снять префикс dd/ee (1 байт), взять ровно 16 байт (без домена)
        raw = secret_hex[1:] if secret_hex[:1] in (b"\xdd", b"\xee") else secret_hex
        self.secret = raw[:16]
        self.dc_id = dc_id
        hs = bytearray(os.urandom(64))
        hs[56:60] = ABRIDGED_TAG          # тег в зашифрованной части
        hs[60:62] = dc_id.to_bytes(2, "little")
        hs[62:64] = b"\x00\x00"
        # клиентский enc = серверный dec: key = sha256(hs[8:40]+secret), iv = hs[40:56]
        self.enc_key = hashlib.sha256(bytes(hs[8:40]) + self.secret).digest()
        self.enc_iv = bytes(hs[40:56])
        # клиентский dec = серверный enc: enc_prekey_and_iv = hs[8:56][::-1]
        rev = bytes(hs[8:56][::-1])
        self.dec_key = hashlib.sha256(rev[:32] + self.secret).digest()
        self.dec_iv = bytes(rev[32:48])
        self.handshake = bytes(hs)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self.enc = Cipher(algorithms.AES(self.enc_key), modes.CTR(self.enc_iv)).encryptor()
        self.dec = Cipher(algorithms.AES(self.dec_key), modes.CTR(self.dec_iv)).decryptor()

    def connect(self, server, port, timeout=6):
        self.sock = socket.create_connection((server, port), timeout=timeout)
        self.sock.settimeout(timeout)
        # как в Telethon: шифруем все 64 байта CTR-потоком, но в заголовок
        # кладём plaintext[0:56] + cipher[56:64] — ключ сервер выводит из RAW-байт
        full_enc = self.enc.update(bytes(self.handshake))
        header = bytearray(self.handshake)
        header[56:64] = full_enc[56:64]
        self.sock.sendall(bytes(header))

    def send_frame(self, payload: bytes):
        inner = b"\x00" * 8 + struct.pack("<Q", int(time.time() * 2**32)) \
                + struct.pack("<i", len(payload)) + payload
        pad = (-len(inner)) % 16
        inner += b"\x00" * pad
        frame = bytes([len(inner) // 4]) + inner
        self.sock.sendall(self.enc.update(frame))

    def recv_frame(self):
        n = self._recv_exact(1)
        if n is None:
            return None
        ln = n[0] * 4
        data = self._recv_exact(ln)
        if data is None:
            return None
        return self.dec.update(data)

    def _recv_exact(self, cnt):
        buf = b""
        while len(buf) < cnt:
            chunk = self.sock.recv(cnt - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

def check_proxy_dd(server, port, secret_hex, dc_id=2, timeout=6):
    """True + время отклика, если через прокси проходит настоящий MTProto-хендшейк."""
    secret = bytes.fromhex(secret_hex)
    t0 = time.time()
    try:
        c = Obf2Client(secret, dc_id)
        c.connect(server, port, timeout)
        # req_pq#60469778: ctor + nonce16
        nonce = os.urandom(16)
        body = b"\x78\x97\x46\x60" + nonce
        inner = b"\x00" * 8 + struct.pack("<Q", int(time.time() * 2**32)) \
                + struct.pack("<i", len(body)) + body
        pad = (-len(inner)) % 16
        inner += b"\x00" * pad
        c.sock.sendall(c.enc.update(bytes([len(inner) // 4]) + inner))
        # ответ: abridged-фрейм, расшифровываем dec-потоком
        rl = c.sock.recv(1)
        if not rl:
            return False, None, "нет ответа"
        resp = c.dec.update(c._recv_exact(rl[0] * 4) or b"")
        # resPQ#05162463 + наш nonce внутри
        if resp[20:24] == b"\x63\x24\x16\x05" and resp[24:40] == nonce:
            return True, int((time.time() - t0) * 1000), "resPQ ok"
        return False, None, "невалидный ответ"
    except Exception as e:
        return False, None, type(e).__name__
