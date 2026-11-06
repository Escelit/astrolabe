pragma circom 2.0.0;

template Linear3() {
    signal input x;
    signal input y;
    signal input z;
    signal output out;
    out <== x * y + z;
}

component main {public [x, y]} = Linear3();
