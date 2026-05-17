# Contributing to @pq-jwt/hybrid

Thank you for helping make post-quantum migration
accessible to every developer.

## Before you start

- Open an issue first for any significant change
- All contributions must keep the full test suite passing
- Never implement your own cryptographic primitives
- Only use @noble/curves, @noble/post-quantum, and @noble/hashes underneath

## Setup

```bash
git clone https://github.com/pq-jwt/PQ-JWT-Hybrid
cd PQ-JWT-Hybrid
npm install
npm test
```

## Making a change

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Make your change
4. Run tests: `npm test` and `npm run test:ecosystem`
5. Open a Pull Request against `main`

## What we welcome

- Bug fixes with a failing test that proves the fix
- Documentation improvements
- Performance improvements that do not change behaviour
- New test cases for edge cases

## What we do not accept

- Custom cryptographic implementations
- Breaking API changes without discussion
- Changes that reduce test coverage
