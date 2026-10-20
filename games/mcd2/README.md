# Minecraft Dungeons 2, milestone 1

This tree loads the base NSP `0100A7C01B792000`. The pinned file hash is in `assets/expected-base.json`. The repository does not contain the game, keys, or decrypted bytes.

The probe and the loader are the milestone. Graphics and Switch service implementations wait until a local probe shows which services this game imports. The rewrite step calls the existing native NSO rewriter. It does not apply Tears of the Kingdom addresses.

## Probe

On the Mac that has your base NSP and your own `prod.keys`:

```sh
python3 -m pip install -r games/mcd2/requirements.txt
python3 games/mcd2/scripts/probe_metadata.py \
  --nsp /path/to/base.nsp \
  --keys /path/to/prod.keys \
  --build-dir "$HOME/Games/MCD2_build"
```

`--build-dir` must be outside the git checkout. Decrypted modules are written only there.

Success is exit 0 and stdout that starts with `status: ok`, then `nsp_sha256` equal to `expected_nsp_sha256`, `title_id: 0100A7C01B792000`, one `nca:` line per NCA, and one `module:` block per ExeFS member. NSO blocks include `build_id`, `sdk_version`, `segment:` lines, `import:`, `export:`, and `service:`. A `section_skipped:` line means that section's media range does not fit in the NCA file, so the probe did not read it. ExeFS is still read when its own range fits. A hash mismatch exits 2, prints both hashes, and writes nothing.

Before it reads any section body, the probe compares every section end with that NCA's size. If any Program section with the ExeFS filesystem type ends past the file, the probe exits 2. An in-range PartitionFS section that has no `main.npdm` (a logo partition is that shape) does not cancel the check. It does not read past the file or fill the gap. Stderr prints each `nca:` line, then `section_end:` (byte_end and nca_size), then `section_header:` (the FS-header SHA-256 stored in the NCA header against the SHA-256 of that header), then `cnmt:` / `cnmt_digest:` lines, then `probe: file appears truncated: expected >= N bytes` with the section's media and byte offsets. N is the furthest section end in that Program NCA. Each `cnmt:` line is one content record: content id, content type, listed size, actual size, listed SHA-256, and the SHA-256 of the NCA bytes in the NSP. `actual_size=absent` means that content id is not an NCA in this NSP. A listed size and hash that match the file mean this is the published NCA and the section table still points outside it. A larger listed size, or a different hash, means these bytes are not that published NCA. The probe prints sizes and hashes only. A common ticket in the NSP is decrypted with `titlekek_XX` from `prod.keys`. This probe does not read `title.keys`.

ExeFS encryption type 3 is AES-CTR. Type 0 is read as AES-CTR. Type 1 is plaintext. Type 2 is AES-XTS from key-area keys 0 and 1. Type 5 leaves the hash table plaintext and decrypts the PFS0 with AES-CTR. Types 4 and 6 with empty BKTR tables use that same CTR path. Any other value, a personalized ticket, or a non-empty BKTR table exits 2. Stderr prints every `nca:` line first, then `probe:` with `fs_type`, `hash_type`, `encryption_type`, `ticket_key_generation`, and `titlekey_type`.

`sdk_version: absent` means the rodata string `sdk_version:` was not found. That is a report, not a failed probe.

## Rewrite and map

```sh
python3 games/mcd2/scripts/prepare_load.py --build-dir "$HOME/Games/MCD2_build"
make -C games/mcd2 host
games/mcd2/build/mcd2-native "$HOME/Games/MCD2_build/rewritten" map
games/mcd2/build/mcd2-native "$HOME/Games/MCD2_build/rewritten" load
```

`make host` on Apple silicon links the gate. Run that command on the Mac. A binary built on another OS maps and resolves the entry, then refuses to call it.

`map` success is exit 0 and one `[mcd2] mapped <name>` line per module, one `[mcd2] relocated` line, and `[mcd2] entry nn::init::Start <module>+0x...` or `[mcd2] entry nnMain <module>+0x...`. It does not enter the game.

`load` success on Apple silicon is those lines plus `[mcd2] ENTER nn::init::Start`. `[mcd2] ENTER nnMain` means the SDK called `nnMain` through its jump slot, or `nnMain` was the only entry symbol and the loader called it. A later `[mcd2] fault signal ...` or `[mcd2] gate ...` line is the first host gap. It is progress, not a finished boot. The first gate exits on purpose so the log stops at the first `svc` or timer.

`prepare_load.py` has not been run on this title. If the rewriter stops, the log is `$HOME/Games/MCD2_build/logs/patch-<module>.log`. A missing `DT_HASH` on a module that has call windows is a known gap in the rewriter.
