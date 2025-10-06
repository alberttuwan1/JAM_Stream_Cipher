class JAMStreamCipherBytes:
  """
  Byte-based cipher with variable-length keys (1–4 bytes).
  - keys: list[bytes]
  - keys[0] is overwritten to 4-byte sum-of-squares (mod 2^32).
  - Two rounds with a reversal between rounds.
  """

  def __init__(self, seed: int = 0, keys: list[bytes] | None = None):
    self.seed = seed
    self.rng = np.random.default_rng(seed)

    if keys is None:
      ks = [b"\x00\x00\x00\x00"]
      n_keys = self.rng.integers(8, 33)
      for _ in range(n_keys):
        ln = int(self.rng.integers(8, 17))  # 8-16
        ks.append(bytes(int(self.rng.integers(0, 256)) for _ in range(ln)))
      self.keys = ks
    else:
      if not isinstance(keys, list) or not all(isinstance(k, (bytes, bytearray)) for k in keys):
        raise TypeError("keys must be a list of bytes/bytearray")
      if len(keys) < 2:
        raise ValueError("Provide at least 2 keys (k0 + at least one more).")
      if any(len(k) == 0 for k in keys[1:]):
        raise ValueError("All keys[1:] must be 1..4 bytes.")
      self.keys = [bytes(k) for k in keys]

    self.cipher_keys = self._with_sum_squares_key0(self.keys)
    self.rounds = 2

  @staticmethod
  def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0

  @staticmethod
  def _bytes_from_int(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big") if n > 0 else b""

  def _with_sum_squares_key0(self, keys: list[bytes]) -> list[bytes]:
    sum_sq = 0
    for k in keys:
      v = self._int_from_bytes(k)
      sum_sq += v * v
    k0 = self._bytes_from_int(sum_sq % (1 << 32), 4)
    out = list(keys)
    out[0] = k0
    for i, k in enumerate(out[1:], start=1):
      ln = len(k)
      if ln == 0:
        raise ValueError(f"Key[{i}] must be 1..4 bytes, got {ln}.")
    return out

  def _round_encrypt(self, data: bytes) -> bytes:
    res = bytearray()
    data_idx = 0
    key_idx = 0
    key_size = len(self.cipher_keys)
    N = len(data)

    while data_idx < N:
      key = self.cipher_keys[key_idx]
      cs = len(key)
      L = min(cs, N - data_idx)
      chunk = data[data_idx: data_idx + L]

      shift = self._int_from_bytes(key[:L])
      mod = 1 << (8 * L)

      # Encryption
      enc_val = ((self._int_from_bytes(chunk) + shift) % mod) ^ shift
      enc_chunk = self._bytes_from_int(enc_val, L)
      res.extend(enc_chunk)

      # Key Scheduling
      p_first = self._int_from_bytes(chunk)
      c_last  = self._int_from_bytes(enc_chunk)
      key_idx = (((p_first + c_last) ^ p_first) + key_idx) % key_size

      data_idx += L

    return bytes(res)

  def _round_decrypt(self, data: bytes) -> bytes:
    res = bytearray()
    data_idx = 0
    key_idx = 0
    key_size = len(self.cipher_keys)
    N = len(data)

    while data_idx < N:
      key = self.cipher_keys[key_idx]
      cs = len(key)
      L = min(cs, N - data_idx)
      chunk = data[data_idx: data_idx + L]

      shift = self._int_from_bytes(key[:L])
      mod = 1 << (8 * L)

      dec_val = ((self._int_from_bytes(chunk) ^ shift) - shift) % mod
      dec_chunk = self._bytes_from_int(dec_val, L)
      res.extend(dec_chunk)

      p_first = self._int_from_bytes(dec_chunk)
      c_last = self._int_from_bytes(chunk)
      key_idx = (((p_first + c_last) ^ p_first) + key_idx) % key_size

      data_idx += L

    return bytes(res)

  def encrypt(self, plaintext: bytes | bytearray) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
      raise TypeError("Plaintext must be bytes or bytearray")
    data = bytes(plaintext)
    r1 = self._round_encrypt(data[::-1])
    r2 = self._round_encrypt(r1[::-1])
    return r2

  def decrypt(self, ciphertext: bytes | bytearray) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
      raise TypeError("Ciphertext must be bytes or bytearray")
    data = bytes(ciphertext)
    d2 = self._round_decrypt(data)[::-1]
    d1 = self._round_decrypt(d2)[::-1]
    return d1

  def show_keys(self):
    print("------ BEGIN KEYS ------")
    for i, k in enumerate(self.cipher_keys):
      print(f"Key[{i}] (len={len(k)}): {k.hex()}")
    print("------  END KEYS  ------")
