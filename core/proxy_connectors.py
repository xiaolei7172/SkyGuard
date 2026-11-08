#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
代理协议连接器

对上层只暴露一个函数：open_tunnel(node, host, port) -> socket
内部按节点类型走不同的协议栈：

  ss      Shadowsocks AEAD（aes-128/192/256-gcm、chacha20-ietf-poly1305）
  trojan  Trojan over TLS（SHA224 口令握手）
  http    HTTP CONNECT 上游（支持 Basic 认证）
  socks5  SOCKS5 上游（支持用户名口令认证）
"""

import hashlib
import ipaddress
import os
import socket
import ssl
import struct

from utils.logger import logger

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.hashes import SHA1
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover - 缺依赖时只影响 Shadowsocks
    HAVE_CRYPTO = False

DEFAULT_TIMEOUT = 10.0
MAX_CHUNK = 0x3FFF


class ConnectorError(Exception):
    """隧道建立失败。"""


# ----------------------------------------------------------------------
# Shadowsocks AEAD
# ----------------------------------------------------------------------
def evp_bytes_to_key(password, key_len):
    """OpenSSL EVP_BytesToKey(MD5) 派生主密钥，与 SS 规范一致。"""
    if isinstance(password, str):
        password = password.encode("utf-8")
    out = b""
    prev = b""
    while len(out) < key_len:
        prev = hashlib.md5(prev + password).digest()
        out += prev
    return out[:key_len]


def hkdf_sha1(key, salt, length, info=b"ss-subkey"):
    hkdf = HKDF(algorithm=SHA1(), length=length, salt=salt, info=info)
    return hkdf.derive(key)


_CIPHER_SPECS = {
    "aes-128-gcm": (16, AESGCM) if HAVE_CRYPTO else (16, None),
    "aes-192-gcm": (24, AESGCM) if HAVE_CRYPTO else (24, None),
    "aes-256-gcm": (32, AESGCM) if HAVE_CRYPTO else (32, None),
    "chacha20-ietf-poly1305": (32, ChaCha20Poly1305) if HAVE_CRYPTO else (32, None),
}


class _Nonce:
    """12 字节小端递增计数器。"""

    def __init__(self):
        self.value = bytearray(12)

    def next(self):
        current = bytes(self.value)
        for i in range(12):
            self.value[i] = (self.value[i] + 1) & 0xFF
            if self.value[i]:
                break
        return current


class AeadWriter:
    """把明文切片加密后写入 socket（长度字段也加密）。"""

    def __init__(self, sock, subkey, cipher_name):
        key_len, factory = _CIPHER_SPECS[cipher_name]
        self.sock = sock
        self.aead = factory(subkey)
        self.nonce = _Nonce()

    def send(self, data):
        total = 0
        view = memoryview(data)
        while view:
            chunk = view[:MAX_CHUNK]
            view = view[MAX_CHUNK:]
            length = struct.pack(">H", len(chunk))
            blob = self.aead.encrypt(self.nonce.next(), length, None)
            blob += self.aead.encrypt(self.nonce.next(), bytes(chunk), None)
            self.sock.sendall(blob)
            total += len(chunk)
        return total

    def flush(self):
        return None


class AeadReader:
    """从 socket 读取加密帧并还原明文。"""

    def __init__(self, sock, subkey, cipher_name):
        self.sock = sock
        self.aead = _CIPHER_SPECS[cipher_name][1](subkey)
        self.nonce = _Nonce()
        self.buffer = b""
        self.eof = False

    def _read_exact(self, n):
        parts = []
        while n > 0:
            chunk = self.sock.recv(n)
            if not chunk:
                self.eof = True
                break
            parts.append(chunk)
            n -= len(chunk)
        return b"".join(parts)

    def _read_frame(self):
        head = self._read_exact(2 + 16)
        if len(head) < 18:
            self.eof = True
            return b""
        length = struct.unpack(">H", self.aead.decrypt(self.nonce.next(), head, None))[0]
        if length == 0 or length > MAX_CHUNK:
            self.eof = True
            return b""
        body = self._read_exact(length + 16)
        if len(body) < length + 16:
            self.eof = True
            return b""
        return self.aead.decrypt(self.nonce.next(), body, None)

    def recv(self, bufsize):
        while not self.buffer and not self.eof:
            self.buffer = self._read_frame()
        data, self.buffer = self.buffer[:bufsize], self.buffer[bufsize:]
        return data


# ----------------------------------------------------------------------
# 地址编码
# ----------------------------------------------------------------------
def encode_address(host, port, include_atyp=True):
    """SOCKS5 风格地址：ATYP + ADDR + PORT。"""
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            atyp, addr = 1, ip.packed
        else:
            atyp, addr = 4, ip.packed
    except ValueError:
        raw = host.encode("idna") if host else b""
        atyp, addr = 3, bytes([len(raw)]) + raw
    head = bytes([atyp]) if include_atyp else b""
    return head + addr + struct.pack(">H", int(port))


def _recv_exact(sock, n):
    parts = []
    while n > 0:
        chunk = sock.recv(n)
        if not chunk:
            raise ConnectorError("上游连接被关闭")
        parts.append(chunk)
        n -= len(chunk)
    return b"".join(parts)


# ----------------------------------------------------------------------
# 各协议实现
# ----------------------------------------------------------------------
def _open_ss(node, host, port, timeout):
    if not HAVE_CRYPTO:
        raise ConnectorError("缺少 cryptography 依赖，无法使用 Shadowsocks")
    key_len, factory = _CIPHER_SPECS.get(node.cipher, (0, None))
    if not factory:
        raise ConnectorError(f"不支持的加密方式: {node.cipher}")

    sock = socket.create_connection((node.server, node.port), timeout=timeout)
    sock.settimeout(timeout)
    master = evp_bytes_to_key(node.password, key_len)

    salt = os.urandom(key_len)
    sock.sendall(salt)
    writer = AeadWriter(sock, hkdf_sha1(master, salt, key_len), node.cipher)
    writer.send(encode_address(host, port))

    reply_salt = _recv_exact(sock, key_len)
    reader = AeadReader(sock, hkdf_sha1(master, reply_salt, key_len), node.cipher)
    return sock, reader, writer


def _open_trojan(node, host, port, timeout):
    raw = socket.create_connection((node.server, node.port), timeout=timeout)
    raw.settimeout(timeout)

    context = ssl.create_default_context()
    if node.skip_cert_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    server_name = node.sni or node.server
    try:
        sock = context.wrap_socket(raw, server_hostname=server_name)
    except ssl.SSLError:
        raw.close()
        # 自签证书且未勾选忽略校验时，退一步给出明确原因
        raise ConnectorError(f"TLS 握手失败（{server_name}），该节点可能使用自签证书")

    digest = hashlib.sha224(node.password.encode("utf-8")).hexdigest().encode()
    header = digest + b"\r\n" + b"\x01" + encode_address(host, port) + b"\r\n"
    sock.sendall(header)
    return sock, None, None


def _open_http(node, host, port, timeout):
    sock = socket.create_connection((node.server, node.port), timeout=timeout)
    sock.settimeout(timeout)
    target = f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if node.username:
        import base64
        token = base64.b64encode(f"{node.username}:{node.password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())

    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1024)
        if not chunk:
            raise ConnectorError("HTTP 上游提前关闭连接")
        head += chunk
        if len(head) > 16384:
            raise ConnectorError("HTTP 上游响应异常")
    status = head.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
    if " 200" not in status:
        sock.close()
        raise ConnectorError(f"HTTP 上游拒绝: {status}")
    return sock, None, None


def _open_socks5(node, host, port, timeout):
    sock = socket.create_connection((node.server, node.port), timeout=timeout)
    sock.settimeout(timeout)

    methods = b"\x00\x02" if node.username else b"\x00"
    sock.sendall(bytes([5, len(methods)]) + methods)
    reply = _recv_exact(sock, 2)
    if reply[0] != 5:
        raise ConnectorError("SOCKS5 上游响应非法")
    method = reply[1]
    if method == 0x02:
        if not node.username:
            raise ConnectorError("SOCKS5 上游要求认证")
        user = node.username.encode()
        pwd = node.password.encode()
        sock.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
        auth = _recv_exact(sock, 2)
        if auth[1] != 0:
            raise ConnectorError("SOCKS5 认证失败")
    elif method != 0x00:
        raise ConnectorError("SOCKS5 上游不支持无认证方式")

    sock.sendall(b"\x05\x01\x00" + encode_address(host, port))
    head = _recv_exact(sock, 4)
    if head[0] != 5 or head[1] != 0:
        raise ConnectorError(f"SOCKS5 连接失败，返回码 {head[1] if len(head) > 1 else '?'}")
    atyp = head[3]
    if atyp == 1:
        _recv_exact(sock, 4)
    elif atyp == 3:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length)
    elif atyp == 4:
        _recv_exact(sock, 16)
    _recv_exact(sock, 2)
    return sock, None, None


_OPENERS = {
    "ss": _open_ss,
    "trojan": _open_trojan,
    "http": _open_http,
    "socks5": _open_socks5,
}


def open_tunnel(node, host, port, timeout=DEFAULT_TIMEOUT):
    """
    通过节点打开到 host:port 的隧道。

    Returns:
        (socket, reader, writer)  reader/writer 仅 Shadowsocks 有值
    """
    opener = _OPENERS.get(node.type)
    if not opener:
        raise ConnectorError(f"暂不支持的协议: {node.type}")
    sock, reader, writer = opener(node, host, port, timeout)
    try:
        sock.settimeout(None)
    except OSError:
        pass
    return sock, reader, writer


def probe_node(node, host="www.gstatic.com", port=80, timeout=5.0):
    """测节点可用性，返回毫秒数；失败返回 None。"""
    import time

    started = time.perf_counter()
    sock = None
    try:
        sock, _, _ = open_tunnel(node, host, port, timeout=timeout)
        return int((time.perf_counter() - started) * 1000)
    except Exception as e:
        logger.debug(f"节点测速失败 {node.name}: {e}")
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
