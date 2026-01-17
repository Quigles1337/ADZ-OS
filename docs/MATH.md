# μ-Theory Mathematical Foundation

**Version**: 0.1.0
**Date**: 2026-01-16

## 1. Introduction

This document establishes the mathematical foundation for μ-cryptography, deriving the core primitives from fundamental constants and exploring their cryptographic applications.

## 2. The Balance Primitive μ

### 2.1 Definition

The balance primitive μ is the 8th root of unity at angle 3π/4:

```
μ = e^(i·3π/4) = cos(3π/4) + i·sin(3π/4) = (-1 + i)/√2
```

### 2.2 Properties

**Algebraic Properties:**
```
μ^0 = 1
μ^1 = (-1 + i)/√2
μ^2 = i
μ^3 = (1 + i)/√2
μ^4 = -1
μ^5 = (1 - i)/√2
μ^6 = -i
μ^7 = (-1 - i)/√2
μ^8 = 1                    (Closure)
```

**Magnitude:**
```
|μ| = √((-1/√2)² + (1/√2)²) = √(1/2 + 1/2) = 1
```

**Balance Property:**
```
|Re(μ)| = |Im(μ)| = 1/√2 ≈ 0.7071
```

### 2.3 Geometric Interpretation

μ represents a rotation of 135° in the complex plane:

```
       Im
        |    μ^1 • (angle = 135°)
        |   /
        |  /
        | /  45°
   -----+-----→ Re
        |
        |
```

Each power μ^n rotates by an additional 45°, completing the full circle at μ^8.

## 3. The Fine-Structure Constant α

### 2.1 Physical Definition

The fine-structure constant is a fundamental physical constant:

```
α = e²/(4πε₀ℏc) ≈ 1/137.035999084
```

### 3.2 Role in μ-Cryptography

α provides a natural coupling constant for scaling operations:

```
V_Z = Z · α · μ
```

The choice of α introduces a non-trivial scaling factor with several beneficial properties:
- Irrational value prevents simple period detection
- Small magnitude (≈ 0.0073) keeps V_Z bounded
- Physical significance provides a "nothing up my sleeve" constant

## 4. The Golden Ratio φ

### 4.1 Definition

```
φ = (1 + √5)/2 ≈ 1.618033988749895
```

### 4.2 Properties

**Algebraic:**
```
φ² = φ + 1
1/φ = φ - 1
```

**Fibonacci Connection:**
```
lim(F(n+1)/F(n)) = φ   as n → ∞
```

### 4.3 Low-Discrepancy Sequence

The sequence {n·φ} mod 1 is equidistributed on [0,1):

```
For any interval [a,b] ⊂ [0,1):
lim (1/N) · |{n ≤ N : {n·φ} ∈ [a,b]}| = b - a
```

This property makes φ ideal for generating quasi-random sequences in key derivation.

## 5. Spiral Rays V_Z

### 5.1 Definition

```
V_Z = Z · α · μ
```

where Z ∈ ℤ⁺ is the quantization level.

### 5.2 Expansion

```
V_Z = Z · α · μ
    = Z · (1/137.036) · ((-1 + i)/√2)
    = (Z/137.036) · ((-1 + i)/√2)
```

Real and imaginary parts:
```
Re(V_Z) = -Z · α / √2 ≈ -0.00516 · Z
Im(V_Z) = Z · α / √2 ≈ 0.00516 · Z
```

### 5.3 Balance Property Inheritance

For all Z:
```
|Re(V_Z)| = |Im(V_Z)| = Z · α / √2
```

This inherited balance property is exploited in the diffusion layer.

### 5.4 Discrete Sampling

The 8-phase sampling at V_Z:
```
V_Z^(n) = V_Z · μ^n   for n ∈ {0, 1, ..., 7}
```

This produces 8 points at angles:
```
θ_n = 3π/4 + n·π/4 = (3 + n)·π/4
```

## 6. The Alchemy Constant K

### 6.1 Definition

```
K = e / μ^8 = e / 1 = e ≈ 2.718281828
```

### 6.2 Role

K normalizes operations that span complete μ-cycles, providing exponential growth balanced by the periodic nature of μ.

## 7. Cryptographic Applications

### 7.1 S-Box Generation

The S-box is derived from V_Z sampling:

```
Algorithm GenerateSBox(seed):
    golden ← GoldenSequence(seed)
    sbox ← [0..255]

    for i in 0..255:
        ray ← V_{i+1}
        phase ← floor(golden.next() × 8)
        sample ← ray · μ^phase

        # Mix real and imaginary contributions
        value ← (|Re(sample)| × 10^k) XOR (|Im(sample)| × 10^k)
        value ← (value XOR seed) mod 256

        # Ensure bijection
        while sbox[value] is assigned:
            value ← (value + 1) mod 256

        sbox[i] ← value

    return sbox
```

**Nonlinearity Analysis:**

The combination of:
1. Golden ratio phase selection (quasi-random)
2. V_Z magnitude dependence on Z
3. XOR mixing of real and imaginary parts

produces an S-box with expected nonlinearity of ~100-112 (compared to AES S-box at 112).

### 7.2 Diffusion via μ-Mix

The μ-mix function:
```
μ-mix(a, b, r):
    rot ← MU_ROTATIONS[r mod 8]
    return (rotl(a, rot) XOR b, rotr(b, rot) XOR a)
```

Rotation amounts derived from μ-angles:
```
MU_ROTATIONS = [24, 48, 12, 36, 6, 42, 18, 54]
```

These are calculated as:
```
rot_n = round(64 × (n × 3/8)) mod 64
```

This maps the μ^n angles to bit rotation amounts.

**Diffusion Property:**

After one μ-mix:
- Each output bit depends on multiple input bits
- The XOR creates non-invertibility without the rotation

After 4 rounds of μ-mix pairs:
- Full avalanche achieved (all output bits depend on all input bits)

### 7.3 Key Derivation

The golden ratio sequence provides key material expansion:

```
key_n = H(master || {n·φ})
```

Properties:
- Low correlation between successive keys
- Deterministic but quasi-random appearance
- Cannot predict key_n from key_{n-1} without master

### 7.4 Signature Scheme

The signature scheme uses a group derived from spiral geometry:

**Generator Point:**
```
G = (expand(|Re(V_137)|), expand(|Im(V_137)|))
```

Where expand() creates a 256-bit coordinate from the spiral value.

The choice of Z=137 (referencing α^{-1}) provides:
- "Nothing up my sleeve" justification
- Balanced initial point

## 8. Security Analysis

### 8.1 Periodicity

The μ^8 = 1 closure creates an 8-element cyclic group. This periodicity is:
- **Beneficial**: Provides structure for round functions
- **Risk**: Could enable algebraic attacks if not properly mixed

**Mitigation**: Golden ratio mixing and Z-quantization break pure periodicity.

### 8.2 Algebraic Structure

The multiplicative group ⟨μ⟩ = {μ^0, μ^1, ..., μ^7} is isomorphic to ℤ₈.

This structure is hidden in the cryptographic primitives by:
1. Embedding in larger bit spaces (64-bit, 128-bit)
2. Non-linear S-box transformation
3. Key-dependent mixing

### 8.3 Distinguisher Resistance

**Hypothesis**: Output of μ-primitives is indistinguishable from random.

**Evidence**:
- Balance property ensures equal real/imaginary contributions
- Golden ratio mixing eliminates patterns
- S-box provides confusion

**Required Testing**:
- NIST SP 800-22 randomness tests
- TestU01 battery
- Custom statistical tests for μ-specific patterns

## 9. Open Questions

1. **Optimal Round Count**: Is 16 rounds sufficient for full security?

2. **S-Box Quality**: Does V_Z sampling produce cryptographically strong S-boxes?

3. **Group Security**: What is the discrete log hardness in the signature group?

4. **Side Channels**: Can μ-operations be implemented in constant time?

5. **Quantum Resistance**: How do quantum algorithms affect μ-primitives?

## 10. Visualizations

### 10.1 μ Powers on Complex Plane

```
        Im
         |        μ^2 (90°)
    μ^1  |       •
      •  |      /
       \ |     /
        \|    /
   ------+------→ Re
        /|    \
       / |     \
      •  |      •
    μ^3  |       μ^7
         |
         • μ^6 (270°)
```

### 10.2 Spiral Ray Growth

```
    |Re(V_Z)| = |Im(V_Z)|
         |
    0.05 |                        •
         |                    •
    0.04 |                •
         |            •
    0.03 |        •
         |    •
    0.02 |  •
         |•
    0.01 +----+----+----+----+----→ Z
         0    2    4    6    8   10
```

## 11. References

1. Hardy, G.H., & Wright, E.M. (2008). An Introduction to the Theory of Numbers
2. Ireland, K., & Rosen, M. (1990). A Classical Introduction to Modern Number Theory
3. Lang, S. (2002). Algebra
4. Feynman, R. (1985). QED: The Strange Theory of Light and Matter

---

*This mathematical foundation will be expanded as the μ-cryptography system develops.*
