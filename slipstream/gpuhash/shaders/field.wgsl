// field.wgsl — Pallas base field Fp arithmetic in WGSL.
// 256-bit element = 8 × u32 limbs, little-endian (limb[0] = least significant 32 bits).
// Montgomery constants taken VERBATIM from pasta_curves 0.5.1 (src/fields/fp.rs) so the
// arithmetic matches bit-for-bit. WGSL has no u64 / mulhi, so 32×32→64 is built from
// 16-bit halves and CIOS Montgomery reduction runs on 32-bit limbs.
//
// p  = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
// INV (-p^-1 mod 2^32) = 0xffffffff   (p ≡ 1 mod 2^32)

// p, as u32×8 LE
var<private> P: array<u32, 8> = array<u32, 8>(
    0x00000001u, 0x992d30edu, 0x094cf91bu, 0x224698fcu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x40000000u
);
// R2 = 2^512 mod p, as u32×8 LE  (pasta R2)
var<private> R2: array<u32, 8> = array<u32, 8>(
    0x0000000fu, 0x8c78ecb3u, 0x8b0de0e7u, 0xd7d30dbdu,
    0xc3c95d18u, 0x7797a99bu, 0x7b9cb714u, 0x096d41afu
);

struct Fp { l: array<u32, 8> }

// (lo, hi) = a * b   (32×32 -> 64), built from 16-bit halves.
fn mul32(a: u32, b: u32) -> vec2<u32> {
    let aL = a & 0xffffu; let aH = a >> 16u;
    let bL = b & 0xffffu; let bH = b >> 16u;
    let ll = aL * bL;
    let lh = aL * bH;
    let hl = aH * bL;
    let hh = aH * bH;
    let lo1 = ll + (lh << 16u);  let c1 = select(0u, 1u, lo1 < ll);
    let lo2 = lo1 + (hl << 16u); let c2 = select(0u, 1u, lo2 < lo1);
    let hi = hh + (lh >> 16u) + (hl >> 16u) + c1 + c2;
    return vec2<u32>(lo2, hi);
}

// (lo, hi) = a*b + c + d    (fits in 64 bits)
fn mac(a: u32, b: u32, c: u32, d: u32) -> vec2<u32> {
    let p = mul32(a, b);
    let s1 = p.x + c;  let k1 = select(0u, 1u, s1 < p.x);
    let s2 = s1 + d;   let k2 = select(0u, 1u, s2 < s1);
    return vec2<u32>(s2, p.y + k1 + k2);
}

// (sum, carry) = a + b + carry_in
fn adc(a: u32, b: u32, cin: u32) -> vec2<u32> {
    let s1 = a + b;    let k1 = select(0u, 1u, s1 < a);
    let s2 = s1 + cin; let k2 = select(0u, 1u, s2 < s1);
    return vec2<u32>(s2, k1 + k2);
}

fn geq_p(a: array<u32, 8>) -> bool {
    for (var i = 8u; i > 0u; i = i - 1u) {
        let ai = a[i - 1u];
        let pi = P[i - 1u];
        if (ai > pi) { return true; }
        if (ai < pi) { return false; }
    }
    return true; // equal counts as >= p
}

fn sub_p(a: array<u32, 8>) -> array<u32, 8> {
    var r: array<u32, 8>;
    var borrow = 0u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        let ai = a[i];
        let d1 = ai - P[i];        let b1 = select(0u, 1u, ai < P[i]);
        let d2 = d1 - borrow;      let b2 = select(0u, 1u, d1 < borrow);
        r[i] = d2; borrow = b1 + b2;
    }
    return r;
}

// Montgomery multiply: returns a*b*R^-1 mod p, R = 2^256. CIOS, 8 × 32-bit limbs.
fn mont_mul(a: Fp, b: Fp) -> Fp {
    var t: array<u32, 10>;
    for (var i = 0u; i < 10u; i = i + 1u) { t[i] = 0u; }
    for (var i = 0u; i < 8u; i = i + 1u) {
        // t = t + a * b[i]
        var c = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
            let r = mac(a.l[j], b.l[i], t[j], c);
            t[j] = r.x; c = r.y;
        }
        let r1 = adc(t[8], c, 0u);
        t[8] = r1.x; t[9] = r1.y;
        // m = t[0] * (-p^-1) mod 2^32 = -t[0]
        let m = 0u - t[0];
        // t = (t + m*p) >> 32   (m*p chosen so low limb cancels)
        let r2 = mac(m, P[0], t[0], 0u);  // r2.x == 0
        c = r2.y;
        for (var j = 1u; j < 8u; j = j + 1u) {
            let r = mac(m, P[j], t[j], c);
            t[j - 1u] = r.x; c = r.y;
        }
        let r3 = adc(t[8], c, 0u);
        t[7] = r3.x;
        t[8] = t[9] + r3.y;
    }
    var res: array<u32, 8>;
    for (var i = 0u; i < 8u; i = i + 1u) { res[i] = t[i]; }
    if (t[8] != 0u || geq_p(res)) { res = sub_p(res); }
    var out: Fp; out.l = res; return out;
}

fn fp_add_(a: Fp, b: Fp) -> Fp {
    var r: array<u32, 8>; var c = 0u;
    for (var j = 0u; j < 8u; j = j + 1u) {
        let s = adc(a.l[j], b.l[j], c); r[j] = s.x; c = s.y;
    }
    if (c != 0u || geq_p(r)) { r = sub_p(r); }
    var out: Fp; out.l = r; return out;
}

fn fp_sub_(a: Fp, b: Fp) -> Fp {
    var r: array<u32, 8>; var borrow = 0u;
    for (var j = 0u; j < 8u; j = j + 1u) {
        let d1 = a.l[j] - b.l[j];  let b1 = select(0u, 1u, a.l[j] < b.l[j]);
        let d2 = d1 - borrow;      let b2 = select(0u, 1u, d1 < borrow);
        r[j] = d2; borrow = b1 + b2;
    }
    if (borrow != 0u) {  // add p back
        var c = 0u;
        for (var j = 0u; j < 8u; j = j + 1u) {
            let s = adc(r[j], P[j], c); r[j] = s.x; c = s.y;
        }
    }
    var out: Fp; out.l = r; return out;
}

// a*b mod p, canonical in / canonical out: mont_mul(mont_mul(a,b), R2) = a*b
fn fp_canon_mul(a: Fp, b: Fp) -> Fp {
    var r2: Fp; r2.l = R2;
    return mont_mul(mont_mul(a, b), r2);
}

// ---- storage I/O ----
@group(0) @binding(0) var<storage, read>       lefts:  array<u32>;
@group(0) @binding(1) var<storage, read>       rights: array<u32>;
@group(0) @binding(2) var<storage, read_write> outp:   array<u32>;

fn load_l(node: u32) -> Fp { var f: Fp; let b = node * 8u; for (var i = 0u; i < 8u; i = i + 1u) { f.l[i] = lefts[b + i]; } return f; }
fn load_r(node: u32) -> Fp { var f: Fp; let b = node * 8u; for (var i = 0u; i < 8u; i = i + 1u) { f.l[i] = rights[b + i]; } return f; }
fn store(node: u32, v: Fp) { let b = node * 8u; for (var i = 0u; i < 8u; i = i + 1u) { outp[b + i] = v.l[i]; } }

@compute @workgroup_size(64)
fn fp_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x; let n = arrayLength(&outp) / 8u; if (node >= n) { return; }
    store(node, fp_canon_mul(load_l(node), load_r(node)));
}

@compute @workgroup_size(64)
fn fp_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x; let n = arrayLength(&outp) / 8u; if (node >= n) { return; }
    store(node, fp_add_(load_l(node), load_r(node)));
}

@compute @workgroup_size(64)
fn fp_sub(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x; let n = arrayLength(&outp) / 8u; if (node >= n) { return; }
    store(node, fp_sub_(load_l(node), load_r(node)));
}

// Bench kernel: a chain of mont_muls per element. Output is not meaningful (prevents
// dead-code elimination); used only to measure raw Montgomery-mul throughput.
@compute @workgroup_size(64)
fn fp_mul_chain(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x; let n = arrayLength(&outp) / 8u; if (node >= n) { return; }
    var acc = load_l(node);
    let b = load_r(node);
    for (var k = 0u; k < 256u; k = k + 1u) { acc = mont_mul(acc, b); }
    store(node, acc);
}
