pragma circom 2.0.0;

/*
 * Multiplier2: proves knowledge of a private factor `b` such that `a * b = c`,
 * where `a` is a public input and `c` is a public output.
 *
 * Public signals emitted by snarkjs (outputs first, then public inputs):
 *   s_0 = c (product)
 *   s_1 = a (public factor)
 * Total IC points in VK: n_ic = n_public + 1 = 3.
 */
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main {public [a]} = Multiplier2();
