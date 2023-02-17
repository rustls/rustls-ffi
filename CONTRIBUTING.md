# Contributing

Welcome to rustls-ffi! We're excited to work with you. If you've got a big chunk of
work that you'd like to do, please file an issue before starting on the code, so
we can get on the same page. If you've just got a small tweak, it's fine to send
a PR without filing an issue first.

After you've sent a PR, we ask that you don't rebase, squash, or force push your
branch. This makes it easier to see changes as your PR evolves. Once we approve
your PR, we will squash it into a single commit, with the summary line set to
the summary of your PR, and the description set to the description of your PR.
That way we maintain a linear git history, where each commit corresponds to a
fully reviewed PR that passed tests.

In README.md, under the "Conventions" section, are described the the API
conventions we follow.

All code must be rustfmt'ed, which we enforce in CI. Check
.github/workflows/test.yml for the current Rust version against which we enforce
rustfmt, since rustfmt's output sometimes changes between Rust versions.

## Dev dependencies

If you're making changes to rustls-ffi, you'll need
`cbindgen` (run `cargo install cbindgen`). After you've made your changes,
regenerate the header file:

    make src/rustls.h
