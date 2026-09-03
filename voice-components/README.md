# Optional voice components

This is a component-only build, not an application installer or application
release. The workflow runs only on `codex/voice-components-cloud` in
`chenjiale364-crypto/haomai-desktop-releases`. It does not modify `main` or change
the latest application release.

The cloud downloads the exact Windows Python runtime, dependency archives and
model files from their original publishers. Pinned hashes and a complete file
inventory bind the output to the locally tested component contents. Small
notices, package metadata and audited integration changes are in the recipe.
Downloaded Python packages, executables and model weights are never executed
on the Linux builder. This is content reconstruction, not a GPU inference test.

No personal documents, voice samples, generated media, app configuration,
financial information or private signing key is part of this repository or
workflow. GitHub supplies a short-lived, repository-scoped upload token. The
model-catalog signing key remains on the developer's computer.

The four packages remain separate: engine, IndexTTS 2.5 core, optional Qwen
emotion extension, and existing-app-compatible shared caption models. A client
that already has compatible subtitle models reuses them. This build does not
change the application's natural-emotion/default-duration settings or weaken
strict caption synchronization checks.

ZIP parts are streamed and uploaded one at a time to bound disk use. Every file
must match its reviewed size and SHA-256; failures stop that component. Existing
complete assets with different contents are preserved. A component manifest is
uploaded only after all its files pass verification. The release remains a draft
until a separate local verification and signing step approves publication.

Small provenance corrections are hash-bound to a specific base recipe. They
can select the exact official binary build and reconstruct two installer-created
Python markers, but cannot change any tested file name, size or content hash.
Keeping these corrections separate avoids re-uploading megabytes of otherwise
unchanged inventory when a download location needs correction.

Upstream model code: `index-tts/index-tts` at
`ee40fa7d6c6b8a2c7f06105f9f1e65775b74868c`. Applicable model terms, notices and
required corresponding-source materials accompany the component release.
The original model rightsholders do not endorse or warrant these modifications.
