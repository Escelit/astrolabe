#!/usr/bin/env bash
set -euo pipefail

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Using temporary dir: $WORK_DIR"
cd "$WORK_DIR"

# 1. Multiplier2 (nPublic = 2)
cat << 'C1' > multiplier2.circom
pragma circom 2.0.0;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main {public [a]} = Multiplier2();
C1

# 2. Square (nPublic = 1)
cat << 'C2' > square.circom
pragma circom 2.0.0;

template Square() {
    signal input in;
    signal output out;
    out <== in * in;
}

component main = Square();
C2

# 3. Linear3 (nPublic = 3)
cat << 'C3' > linear3.circom
pragma circom 2.0.0;

template Linear3() {
    signal input x;
    signal input y;
    signal input z;
    signal output out;
    out <== x * y + z;
}

component main {public [x, y]} = Linear3();
C3

circom multiplier2.circom --r1cs --wasm --sym
circom square.circom --r1cs --wasm --sym
circom linear3.circom --r1cs --wasm --sym

# Shared Powers of Tau (bn128, 2^8)
snarkjs powersoftau new bn128 8 pot8_0000.ptau -v
snarkjs powersoftau contribute pot8_0000.ptau pot8_0001.ptau --name="Phase4 Dev Contribution" -v -e="astrolabe phase 4 deterministic dev setup"
snarkjs powersoftau prepare phase2 pot8_0001.ptau pot8_final.ptau -v

# Function to setup and prove circuit
process_circuit() {
    local name="$1"
    local input_json="$2"

    echo "=== Processing $name ==="
    snarkjs groth16 setup "${name}.r1cs" pot8_final.ptau "${name}_0000.zkey"
    snarkjs zkey contribute "${name}_0000.zkey" "${name}_final.zkey" --name="Contrib" -v -e="${name} zkey contrib"
    snarkjs zkey export verificationkey "${name}_final.zkey" "${name}_vk.json"

    echo "$input_json" > "${name}_input.json"
    node "${name}_js/generate_witness.js" "${name}_js/${name}.wasm" "${name}_input.json" "${name}_witness.wtns"
    snarkjs groth16 prove "${name}_final.zkey" "${name}_witness.wtns" "${name}_proof.json" "${name}_public.json"
    snarkjs groth16 verify "${name}_vk.json" "${name}_public.json" "${name}_proof.json"
}

process_circuit "multiplier2" '{"a": "3", "b": "11"}'
process_circuit "square" '{"in": "12"}'
process_circuit "linear3" '{"x": "5", "y": "7", "z": "3"}'

TARGET_DIR="/home/escelit/Desktop/astrolabe/spec/fixtures/snarkjs"
mkdir -p "$TARGET_DIR/multiplier2" "$TARGET_DIR/square" "$TARGET_DIR/linear3"

cp multiplier2.circom "$TARGET_DIR/multiplier2/circuit.circom"
cp multiplier2_input.json "$TARGET_DIR/multiplier2/input.json"
cp multiplier2_vk.json "$TARGET_DIR/multiplier2/verification_key.json"
cp multiplier2_proof.json "$TARGET_DIR/multiplier2/proof.json"
cp multiplier2_public.json "$TARGET_DIR/multiplier2/public.json"

cp square.circom "$TARGET_DIR/square/circuit.circom"
cp square_input.json "$TARGET_DIR/square/input.json"
cp square_vk.json "$TARGET_DIR/square/verification_key.json"
cp square_proof.json "$TARGET_DIR/square/proof.json"
cp square_public.json "$TARGET_DIR/square/public.json"

cp linear3.circom "$TARGET_DIR/linear3/circuit.circom"
cp linear3_input.json "$TARGET_DIR/linear3/input.json"
cp linear3_vk.json "$TARGET_DIR/linear3/verification_key.json"
cp linear3_proof.json "$TARGET_DIR/linear3/proof.json"
cp linear3_public.json "$TARGET_DIR/linear3/public.json"

echo "Fixtures generated successfully!"
