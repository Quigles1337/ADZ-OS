# μ-Cryptography Formal Specification

**Version**: 0.1.0
**Status**: Draft
**Date**: 2026-01-16

## 1. Introduction

This document provides the formal specification for the μ-cryptography suite used in μOS. The cryptographic primitives are based on novel mathematical structures derived from the balance primitive μ and related constants.

## 2. Notation and Definitions

### 2.1 Mathematical Constants

| Symbol | Definition | Value |
|--------|------------|-------|
| μ | Balance primitive | e^(i·3π/4) = (-1 + i)/√2 |
| α | Fine-structure constant | ≈ 1/137.035999084 |
| φ | Golden ratio | (1 + √5)/2 ≈ 1.618033988749895 |
| K | Alchemy constant | e/μ^8 = e |

### 2.2 Key Properties

- **Closure**: μ^8 = 1
- **Balance**: |Re(μ)| = |Im(μ)| = 1/√2
- **Angle**: arg(μ) = 3π/4 = 135°

### 2.3 Spiral Rays

The quantized spiral ray V_Z is defined as:

```
V_Z = Z · α · μ
```

where Z ∈ ℤ⁺ is the quantization level.

## 3. μ-Spiral Cipher

### 3.1 Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Block size | 128 bits | 16 bytes |
| Key size | 256 bits | 32 bytes |
| Rounds | 16 | 2 × μ^8 cycles |
| Nonce size | 96 bits | For CTR/AEAD modes |

### 3.2 Key Schedule

Input: 256-bit key K = (k₀, k₁, k₂, k₃) where each kᵢ is 64 bits

1. Initialize golden sequence G with seed k₀ ⊕ k₂
2. Initialize state S = (k₀, k₁, k₂, k₃)
3. For round r = 0 to 15:
   a. Apply μ-mix: (a, b) ← μ-mix(S₀, S₁, r)
   b. Apply μ-mix: (c, d) ← μ-mix(S₂, S₃, r)
   c. Compute ray constant: RC_r ← |Re(V_{r+1})| ⊕ |Im(V_{r+1})|
   d. Get golden factor: GF_r ← G.next() × 2^64
   e. Set round key: RK_r ← (a ⊕ c ⊕ RC_r, b ⊕ d ⊕ GF_r)
   f. Update state with rotations

Output: 16 round keys RK₀...RK₁₅, each 128 bits

### 3.3 Round Function

For each round r:

1. **Substitution (S-layer)**
   - Apply S-box to each byte
   - S-box generated from V_Z sampling with golden sequence

2. **Permutation (P-layer)**
   - Byte rotation: position i → (i + r·3) mod 16
   - Bit rotation: each byte rotated left by (i + r) mod 8 bits

3. **Diffusion (D-layer)**
   - Split block into (lo, hi) 64-bit halves
   - Apply μ-mix: (lo', hi') ← μ-mix(lo, hi, r)

4. **Key Addition (K-layer)**
   - XOR with round key: block ← block ⊕ RK_r

### 3.4 μ-Mix Function

```
μ-mix(a, b, r):
    rot ← MU_ROTATIONS[r mod 8]    // [24, 48, 12, 36, 6, 42, 18, 54]
    a' ← (a <<< rot) ⊕ b
    b' ← (b >>> rot) ⊕ a
    return (a', b')
```

### 3.5 S-Box Generation

1. Initialize golden sequence with seed
2. For i = 0 to 255:
   a. Compute spiral ray: ray ← V_{i+1}
   b. Get golden phase: phase ← ⌊G.next() × 8⌋
   c. Sample point: sample ← ray.rotate(μ^phase)
   d. Derive value: val ← |Re(sample)| ⊕ |Im(sample)| mod 256
   e. Ensure bijection by collision resolution

### 3.6 Encryption

```
Encrypt(P, K):
    B ← P
    B ← B ⊕ RK₀                    // Initial whitening
    for r = 0 to 15:
        B ← Round(B, r, RK_r)
    B ← B ⊕ RK₁₅                   // Final whitening
    return B
```

### 3.7 Modes of Operation

#### CTR Mode
- Nonce: 96 bits
- Counter: 32 bits, big-endian
- Counter block: nonce || counter

#### AEAD Mode
- Authentication tag: 128 bits
- Polynomial MAC over AAD || ciphertext || lengths

## 4. μ-Hash

### 4.1 Parameters

| Parameter | Value |
|-----------|-------|
| State size | 384 bits (6 × 64-bit words) |
| Rate | 128 bits |
| Capacity | 256 bits |
| Output size | 256 bits |
| Rounds | 24 |

### 4.2 Initialization Vector

IV derived from spiral rays V₁ through V₆:
```
IV_i = |Re(V_i)| ⊕ rotl(|Im(V_i)|, 32)
```

### 4.3 Permutation Function

For each round r = 0 to 23:

1. **Round constant addition**: S₀ ← S₀ ⊕ RC_r
2. **Column mixing (θ)**: Apply μ-mix to pairs
3. **Rotations (ρ)**: S_i ← rotl(S_i, ρ_i)
4. **Position permutation (π)**: Rotate state array
5. **Nonlinear mixing (χ)**: S_i ← S_i ⊕ (¬S_{i+1} ∧ S_{i+2})
6. **S-box layer**: Apply S-box to edge bytes

### 4.4 Padding

- Append 0x80
- Append zeros
- Append 64-bit message length in bits (big-endian)

### 4.5 Squeeze Phase

- Extract first 128 bits
- Permute
- Extract next 128 bits
- Concatenate for 256-bit output

## 5. μ-KDF

### 5.1 HKDF-like Construction

```
Extract(salt, IKM):
    return HMAC-μHash(salt, IKM)

Expand(PRK, info, length):
    T(0) = ""
    T(i) = HMAC-μHash(PRK, T(i-1) || info || i)
    return T(1) || T(2) || ... truncated to length
```

### 5.2 Password-Based KDF

Memory-hard construction inspired by Argon2:
- Time cost: Iteration count
- Memory cost: Working memory size
- Parallelism: Lane count
- Uses golden ratio indexing for memory access pattern

## 6. μ-Signatures

### 6.1 Parameters

| Parameter | Value |
|-----------|-------|
| Private key | 256 bits |
| Public key | 512 bits |
| Signature | 512 bits |

### 6.2 Key Generation

1. Generate random 256-bit scalar s
2. Compute public key: P = s · G
   where G is the generator point

### 6.3 Signing

```
Sign(sk, message):
    k ← H(sk || message)           // Deterministic nonce
    R ← k · G
    e ← H(R || pk || message)
    s ← k + e · sk
    return (R.x, s)
```

### 6.4 Verification

```
Verify(pk, message, (r, s)):
    e ← H(R || pk || message)
    Check: s · G == R + e · pk
```

## 7. μ-CSPRNG

### 7.1 State

- 8 × 64-bit words (512 bits)
- Output buffer: 64 bytes
- Reseed counter

### 7.2 Generation

20 rounds of quarter-round mixing using μ-mix, followed by state addition.

### 7.3 Forward Secrecy

State is advanced after each block generation using golden ratio mixing.

### 7.4 Reseeding

Automatic reseed after 2²⁰ blocks or on demand.

## 8. Security Claims

### 8.1 Computational Security

| Primitive | Security Level |
|-----------|---------------|
| μ-Spiral Cipher | 128-bit |
| μ-Hash (collision) | 128-bit |
| μ-Hash (preimage) | 256-bit |
| μ-Signatures | 128-bit (EUF-CMA) |

### 8.2 Assumptions

- μ-spiral transformations are bijective
- μ-mix provides adequate diffusion
- S-box generated from V_Z sampling has good nonlinearity

## 9. Test Vectors

### 9.1 μ Constant Verification

```
μ.re = -0.7071067811865476
μ.im = 0.7071067811865476
μ^8 = (1.0, 0.0) ± 10^-10
```

### 9.2 Cipher Test Vector

```
Key: 00 01 02 03 ... 1e 1f (32 bytes)
Plaintext: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
(Ciphertext depends on final S-box derivation)
```

## 10. Implementation Notes

### 10.1 Constant-Time Operations

Critical operations must be constant-time:
- Key comparison
- S-box lookup (consider using conditional select)
- Scalar multiplication in signatures

### 10.2 Memory Security

- Zeroize sensitive data on drop
- Avoid copying keys unnecessarily
- Use secure allocators where possible

## 11. References

1. NIST SP 800-38A - Block Cipher Modes
2. RFC 5869 - HKDF
3. NIST SP 800-90A - DRBG
4. Schnorr Signatures

---

*This specification is subject to change pending security analysis and peer review.*
