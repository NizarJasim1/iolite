# Contributing

Issues and pull requests are welcome.

## Setup

```bash
git clone https://github.com/NizarJasim1/iolite.git && cd iolite
python -m iolite demo        # offline end-to-end run
make test                    # full suite, stdlib only
```

Set `ONYX_PATH` to a checkout of [ONYX](https://github.com/NizarJasim1/Onyx) to also run the
compatibility test that checks emitted specs against ONYX's own loaders.

## Ground rules

1. **Nothing leaves the scope guard.** Any new code path that can send a request goes
   through `scope_guard.py` and fails closed.
2. **Passive before live.** New acquisition sources should work on captured or public
   material first. Live steps stay opt-in.
3. **Deterministic output.** Same inputs, byte-identical spec. The golden test checks this.
4. **Propose, don't judge.** IOLITE can rank and explain, never mark something as a finding.
5. **Standard library only** in the core package.

## Adding an extraction source

1. Add the parser and record provenance for every fact it produces.
2. Add a fixture and extend the labeled bundle so `iolite selftest` measures it.
3. Add tests for malformed and hostile input (see `limits.py`).

## License of contributions

IOLITE is released under the PolyForm Noncommercial License 1.0.0 and is also offered
under separate commercial licenses. By opening a pull request you agree that your
contribution is licensed under the same terms and may be included in commercially
licensed versions of IOLITE.
