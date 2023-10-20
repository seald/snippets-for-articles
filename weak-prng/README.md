# Weak PRNG
This project explores how to make a (weak) PRNG out of `Math.random` in V8 which internally uses XorShift128+, and breaks it using [Z3](https://github.com/Z3Prover/z3).

# Run
In Node.js (make sure you use a version [which uses V8 > 7.1](https://v8.dev/blog/math-random), run `npm install && npm start`.

# Acknowledgments
I based the implementation of the Z3 solver out of this project in Python: https://github.com/PwnFunction/v8-randomness-predictor.

I based the implementation of the reverse xorshift128p (which isn't used in the end, because I realized that V8 uses a cache of pregenerated values, and returns them in reverse order, therefore to get the previous value of Math.random, it is not a reverse xorshift128p but a xorshift128p) ouf of https://blog.securityevaluators.com/xorshift128-backward-ff3365dc0c17 who published this repository: https://github.com/TACIXAT/XorShift128Plus.
