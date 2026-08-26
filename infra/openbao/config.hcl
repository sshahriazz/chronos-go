# OpenBao for LOCAL DEVELOPMENT, with storage that survives a restart.
#
# # Why not -dev
#
# Dev mode keeps everything in memory. That is fine until the container
# restarts, at which point the transit engine and the key-encryption key are
# gone — and every subject's personal data in Postgres becomes undecryptable,
# because the data keys were wrapped by a key that no longer exists (ADR-028).
#
# That is not a theoretical concern here: Docker Desktop restarted six times in
# one session and took every registered account with it each time. The symptom
# is not an error — accounts still authenticate, because authentication touches
# no personal data — it is notifications silently failing to resolve an address.
#
# So dev stores its data on a volume like everything else does. The failure it
# removes is the same one production faces when a key store is rebuilt without
# its key material; only the frequency differs.
#
# # This is still NOT a production configuration
#
# One unseal share, a threshold of one, TLS disabled, and the unseal key written
# to a file beside the data it unseals. Production runs a real seal — a threshold
# of several shares held by different people, or auto-unseal against a cloud KMS
# — and never keeps the key next to the ciphertext. What dev borrows from
# production is durability, not custody.

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# The API address the server advertises to itself.
api_addr = "http://127.0.0.1:8200"

# There is deliberately NO disable_mlock here, in either direction.
#
# OpenBao removed mlock support outright, and the server refuses to load a
# config that mentions it at all — `disable_mlock = false` is as fatal as
# `true`. Keeping key material out of swap is now the operating system's job:
# encrypt swap, or disable it. See
# https://openbao.org/docs/install/#post-installation-hardening
#
# The IPC_LOCK capability compose grants is now inert and left in place: it
# costs nothing, and removing it would be a second change to verify for no gain.

ui = false
