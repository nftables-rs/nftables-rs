# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.6.2](https://github.com/nftables-rs/nftables-rs/compare/v0.6.1...v0.6.2)

### 🐛 Bug Fixes

- Clippy string format lint - ([39b5796](https://github.com/nftables-rs/nftables-rs/commit/39b57961da47dd7dedb520b42f3a136e4d4ad1c9))

### 📚 Documentation

- *(expr)* Fix Payload docs - ([11f9657](https://github.com/nftables-rs/nftables-rs/commit/11f9657f42308c238fbbf76319c0956d24936b9c))


## [0.6.1](https://github.com/nftables-rs/nftables-rs/compare/v0.6.0...v0.6.1)

This release adds the command `./nftables-rs schema <export-path>` to export a
*JSON Schema* of our implementation of the nftables JSON API.

### ⛰️ Features

- *(cli)* Add json schema export using schemars - ([79fe2f8](https://github.com/nftables-rs/nftables-rs/commit/79fe2f81ad3ab4d48de5784289914707e608a4af))

### 📚 Documentation

- Update license-mit copyright owner - ([d90ddb9](https://github.com/nftables-rs/nftables-rs/commit/d90ddb9edb3f38ee30dbea050d55db3dff5b6a79))
- Update new github org URL - ([95f1f68](https://github.com/nftables-rs/nftables-rs/commit/95f1f68ae246d87ed74872314ef08c931c68ce61))

Thanks to @joelMuehlena for adding the JSON Schema export.


## [0.6.0](https://github.com/nftables-rs/nftables-rs/compare/v0.5.0...v0.6.0)

This release includes memory optimizations, adds async helpers (optionally via tokio) and improves expressions documentation.

### ⛰️ Features

- *(expr)* [**breaking**] Add documentation, default impls for expressions,
  add attributes to socket expression - ([13c0849](https://github.com/nftables-rs/nftables-rs/commit/13c084968b04bba73a8161f8947f9d4901580a93))
- *(expr)* [**breaking**] Make range fixed-sized array, not slice - ([1ce8021](https://github.com/nftables-rs/nftables-rs/commit/1ce80215bdf4d6ce0d42794127caa11d4b270626))
- *(helper)* Add async helpers - ([81cd4f3](https://github.com/nftables-rs/nftables-rs/commit/81cd4f37387519eb7bfba833e9be13ed5ed728f6))
- *(helper)* Generalize helper arguments - ([021668a](https://github.com/nftables-rs/nftables-rs/commit/021668a9231864d597b9165719df9830ca8b0c92))
- *(helper)* [**breaking**] Make helper APIs accept borrowed values - ([091adb4](https://github.com/nftables-rs/nftables-rs/commit/091adb43134f523c4ae7276d59f87e55e3436d93))
- [**breaking**] Replace Cow<'static, _> with 'a - ([c22a2a4](https://github.com/nftables-rs/nftables-rs/commit/c22a2a47d68888441028e4921711b72ac15aee2a))
- [**breaking**] Reduce stack usage by selectively wrapping large values in Box - ([583b2d5](https://github.com/nftables-rs/nftables-rs/commit/583b2d58cb3a8d55a348752b7ef248a00df899bf))
- [**breaking**] Use `Cow` whenever possible instead of owned values - ([8ddb5ff](https://github.com/nftables-rs/nftables-rs/commit/8ddb5ff132e757b95ac8b4cb8e05295f38a7098e))

### 🐛 Bug Fixes

- *(expr)* [**breaking**] Revert recursive Cow<[Expression]> back to Vec - ([75b7f48](https://github.com/nftables-rs/nftables-rs/commit/75b7f48795fe87857f2e9dfcd859eb5075de30ac))
- *(stmt)* Allow port-range for nat port - ([07d062a](https://github.com/nftables-rs/nftables-rs/commit/07d062a8de0827a8a50f865d9ceaf61975ad8415))
- *(stmt)* [**breaking**] Match anonymous and named quotas - ([61ba8ea](https://github.com/nftables-rs/nftables-rs/commit/61ba8eaec6502674104b77666dc89f8bc052e7ad))
- *(tests)* Fix datatest_stable::harness macro usage - ([3948819](https://github.com/nftables-rs/nftables-rs/commit/3948819e109e4fe66ed1f7a954c9bd6d2f6530e6))

### 📚 Documentation

- *(helper)* Add docs for async helpers - ([3a6be32](https://github.com/nftables-rs/nftables-rs/commit/3a6be325a8f97bc42ca15cc4c4e183aa369c80ac))
- *(readme)* Fix call to apply_ruleset() - ([210e4ee](https://github.com/nftables-rs/nftables-rs/commit/210e4ee7c3eafd265be7e997294ba68571732ecc))
- *(readme)* Update examples - ([4857791](https://github.com/nftables-rs/nftables-rs/commit/48577917d67703819a9b73f3866df0bfaa3773eb))
- Define msrv - ([dfc8517](https://github.com/nftables-rs/nftables-rs/commit/dfc8517372dd8360dac27fbf8859d32b2f8f8bad))

### 🧪 Testing

- *(deserialize)* Generate deserialize tests with harness - ([68332fd](https://github.com/nftables-rs/nftables-rs/commit/68332fd8dfe3d03921b8f0fad64a324ba4b6b326))
- *(stmt)* Extend nat test with port range - ([ad0b46a](https://github.com/nftables-rs/nftables-rs/commit/ad0b46a0f5b6a739e10e0d8b2a39b50547ab02f3))

### ⚙️ Miscellaneous Tasks

- *(msrv)* [**breaking**] Increase msrv to 1.76 - ([76e7e7a](https://github.com/nftables-rs/nftables-rs/commit/76e7e7ad6b277bb63dd632adfe022cccf9959c5c))


## [0.5.0](https://github.com/namib-project/nftables-rs/compare/v0.4.1...v0.5.0)

This release completes documentation for `schema` and adds support for **tproxy**,
**synproxy** and **flow**/**flowtable** statements/objects.

### ⚠️ Breaking Changes

- Enum `stmt::Statement`:
  - adds variants `Flow`, `SynProxy` and `TProxy`,
  - removes variant `CounterRef`,
  - receives a `#[non_exhaustive]` mark.
- Struct `stmt::Counter` became enum.
- Enum `schema::NfListObject` adds variant `SynProxy`.
- Removed functions `schema::Table::new()`, `schema::Table::new()` and `schema::Rule::new()`.

### ⛰️ Features

- *(schema)* [**breaking**] Add default impl, add doc comments - ([abd3156](https://github.com/namib-project/nftables-rs/commit/abd3156e846c13be3a9c8a9df31395580ba0d75b))
- *(schema)* Qualify limit's per-attribute as time unit enum - ([42c399d](https://github.com/namib-project/nftables-rs/commit/42c399d2d26e8cb4ae9324e5315bcb746beb6f10))
- *(stmt)* Implement flow statement - ([a3209cb](https://github.com/namib-project/nftables-rs/commit/a3209cb2c293f64043d96a454dee9970eeda679a))
- Add synproxy statement and list object - ([0108fbf](https://github.com/namib-project/nftables-rs/commit/0108fbfc9ecf6523083b4bd77215431a90e11c16))

### 🐛 Bug Fixes

- *(stmt)* [**breaking**] Fix named counter - ([9f109c5](https://github.com/namib-project/nftables-rs/commit/9f109c51e4b657acf1194e4342f175b0394d2cd8))
- Add doc comment and trait derive to counters - ([617b071](https://github.com/namib-project/nftables-rs/commit/617b071330960cc8092ded5fcbaf91c0579e35d1))
- [**breaking**] Store NfListObjects in heap - ([51ccf10](https://github.com/namib-project/nftables-rs/commit/51ccf106dac1b810eec6d61af602284d594c440a))

### 📚 Documentation

- *(lib)* Add library description - ([2e98483](https://github.com/namib-project/nftables-rs/commit/2e98483b74a75c0e3dfed9dc53cc8d87ee0edda4))
- *(readme)* Add @JKRhb as maintainer - ([021abc1](https://github.com/namib-project/nftables-rs/commit/021abc1cbf636f980084e8390924691fa873d3df))
- *(visitor)* Fix doc comment syntax - ([d8e0c68](https://github.com/namib-project/nftables-rs/commit/d8e0c68391fdaa07c66ebb53e202239fae53be4b))
- Fix long doc comments in expr, stmt - ([290c5bb](https://github.com/namib-project/nftables-rs/commit/290c5bbb0c3890c0fa94b915e27b1d26b48f5042))
- Add doc comments for tproxy - ([e13a5ed](https://github.com/namib-project/nftables-rs/commit/e13a5ed90d9dcc9475e66e64ad0dc29a7bc71514))

### 🧪 Testing

- *(schema)* Add set and map nft/json test - ([03db827](https://github.com/namib-project/nftables-rs/commit/03db827a9a8630a3f10129b91eb47b06cb667c36))
- *(stmt)* Add serialization test for flow, flowtable - ([fd88573](https://github.com/namib-project/nftables-rs/commit/fd8857314d8a611724d753567664fd9301d4299e))
- Refactor nftables-json test script with unshare - ([3799022](https://github.com/namib-project/nftables-rs/commit/3799022069311f47770aa061da5c05bf70e306bb))
- Add test for synproxy - ([910315b](https://github.com/namib-project/nftables-rs/commit/910315ba22a8fc2f38e3d0e2ac84c670deb2ec82))
- Re-convert json data from nftables files - ([1ca5421](https://github.com/namib-project/nftables-rs/commit/1ca5421807e4663087cdcf5801ead27b74eb6b72))


## [0.4.1] - 2024-05-27

### ⚙️ Miscellaneous Tasks

- Add dependabot, git-cliff, release-plz
- Add github issue templates
- Add rust fmt check for pull requests
- Consolidate rust-fmt into rust workflow
- *(dep)* Bump dependencies serde, serde_json, serial_test

### Build

- Add devcontainer configuration

<!-- generated by git-cliff -->
