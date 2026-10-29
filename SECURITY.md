# Security

## Reporting a vulnerability in IOLITE itself

If you find a security problem in IOLITE itself (for example, a way to make the scope
guard allow an out-of-scope request, or a way for a crafted HAR, JS bundle or schema
to run code or write outside the output directory), please don't open a public issue.

Use GitHub's private vulnerability reporting on this repository instead
(**Security → Report a vulnerability**). Include the version or commit, the steps to
reproduce, and what you expected to happen. I'll reply as soon as I can and credit
you in the fix unless you'd rather stay anonymous.

## Using IOLITE responsibly

Most of IOLITE works offline on captures, but live commands send real requests
with your accounts' credentials.

- Only test applications you own, intentionally vulnerable labs, or programs whose
  rules explicitly allow automated testing with multiple accounts.
- Use test accounts you created. Never use other people's credentials.
- Set the scope in the spec as tightly as you can. The scope guard blocks anything
  outside it and treats uncertainty as "don't send".
- Tokens are redacted from specs by default. Don't commit captures, specs or
  engagement files that contain live credentials.

Bugs you find with IOLITE in someone else's product should go to that vendor through
their disclosure process, not here.
