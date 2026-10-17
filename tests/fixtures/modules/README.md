# Synthetic protocol fixtures

These RVF packages contain only an empty Wasm module with a custom data section.
They do not implement sensing and have never been deployed. They are signed by
a public test-only key derived from the phrase in the reproducibility helper;
never use this key as an installation trust anchor. The test loader supplies
fixture authority explicitly; production code has no package or key default.
