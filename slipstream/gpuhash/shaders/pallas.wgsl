// pallas.wgsl — Pallas (y^2 = x^3 + 5, a=0) point ops in WGSL. Requires field.wgsl (Fp,
// fp_canon_mul, fp_add_, fp_sub_, P, and the lefts/rights/outp storage buffers).
//
// Point = Jacobian (X, Y, Z); affine = (X/Z^2, Y/Z^3); identity = Z == 0.
// Addition is the plain group law (SINSEMILLA-SPEC §4: "incomplete add" == group add for
// the non-exceptional inputs that occur). Standard EFD formulas: dbl-2009-l, add-2007-bl.

struct Pt { x: Fp, y: Fp, z: Fp }

// p - 2, u32x8 LE (for Fermat inverse a^(p-2)). p's top set bit is 254.
var<private> P_MINUS_2: array<u32, 8> = array<u32, 8>(
    0xffffffffu, 0x992d30ecu, 0x094cf91bu, 0x224698fcu,
    0x00000000u, 0x00000000u, 0x00000000u, 0x40000000u
);

fn fp_one() -> Fp { var f: Fp; f.l[0] = 1u; for (var i = 1u; i < 8u; i = i + 1u) { f.l[i] = 0u; } return f; }
fn fp_is_zero(a: Fp) -> bool { for (var i = 0u; i < 8u; i = i + 1u) { if (a.l[i] != 0u) { return false; } } return true; }
fn fp_dbl(a: Fp) -> Fp { return fp_add_(a, a); }
fn fp_tri(a: Fp) -> Fp { return fp_add_(fp_dbl(a), a); }

// 2*p (doubling): dbl-2009-l for a = 0.
fn pt_double(p: Pt) -> Pt {
    if (fp_is_zero(p.z)) { return p; }
    let aa = fp_canon_mul(p.x, p.x);
    let bb = fp_canon_mul(p.y, p.y);
    let cc = fp_canon_mul(bb, bb);
    let xpb = fp_add_(p.x, bb);
    let dd = fp_dbl(fp_sub_(fp_sub_(fp_canon_mul(xpb, xpb), aa), cc));
    let ee = fp_tri(aa);
    let ff = fp_canon_mul(ee, ee);
    let x3 = fp_sub_(ff, fp_dbl(dd));
    let y3 = fp_sub_(fp_canon_mul(ee, fp_sub_(dd, x3)), fp_dbl(fp_dbl(fp_dbl(cc)))); // -8C
    let z3 = fp_dbl(fp_canon_mul(p.y, p.z));
    return Pt(x3, y3, z3);
}

// P + Q (P != ±Q, neither identity): add-2007-bl. Handles identity operands explicitly.
fn pt_add(p: Pt, q: Pt) -> Pt {
    if (fp_is_zero(p.z)) { return q; }
    if (fp_is_zero(q.z)) { return p; }
    let z1z1 = fp_canon_mul(p.z, p.z);
    let z2z2 = fp_canon_mul(q.z, q.z);
    let u1 = fp_canon_mul(p.x, z2z2);
    let u2 = fp_canon_mul(q.x, z1z1);
    let s1 = fp_canon_mul(fp_canon_mul(p.y, q.z), z2z2);
    let s2 = fp_canon_mul(fp_canon_mul(q.y, p.z), z1z1);
    let h = fp_sub_(u2, u1);
    let hh = fp_dbl(h);
    let i = fp_canon_mul(hh, hh);
    let j = fp_canon_mul(h, i);
    let r = fp_dbl(fp_sub_(s2, s1));
    let v = fp_canon_mul(u1, i);
    let x3 = fp_sub_(fp_sub_(fp_canon_mul(r, r), j), fp_dbl(v));
    let y3 = fp_sub_(fp_canon_mul(r, fp_sub_(v, x3)), fp_dbl(fp_canon_mul(s1, j)));
    let zs = fp_add_(p.z, q.z);
    let z3 = fp_canon_mul(fp_sub_(fp_sub_(fp_canon_mul(zs, zs), z1z1), z2z2), h);
    return Pt(x3, y3, z3);
}

// Fermat inverse: a^(p-2) mod p. Left-to-right square-and-multiply over bits 254..0 of p-2.
fn fp_inv(a: Fp) -> Fp {
    var r = fp_one();
    var bit_idx: u32 = 255u;
    loop {
        if (bit_idx == 0u) { break; }
        bit_idx = bit_idx - 1u;            // 254 .. 0
        r = fp_canon_mul(r, r);
        let b = (P_MINUS_2[bit_idx / 32u] >> (bit_idx % 32u)) & 1u;
        if (b == 1u) { r = fp_canon_mul(r, a); }
    }
    return r;
}

// Jacobian -> affine (x, y), one inversion. Identity (z==0) -> (0, 0).
fn pt_to_affine(p: Pt) -> array<u32, 16> {
    var o: array<u32, 16>;
    if (fp_is_zero(p.z)) { for (var i = 0u; i < 16u; i = i + 1u) { o[i] = 0u; } return o; }
    let zinv = fp_inv(p.z);
    let zinv2 = fp_canon_mul(zinv, zinv);
    let zinv3 = fp_canon_mul(zinv2, zinv);
    let x = fp_canon_mul(p.x, zinv2);
    let y = fp_canon_mul(p.y, zinv3);
    for (var i = 0u; i < 8u; i = i + 1u) { o[i] = x.l[i]; o[i + 8u] = y.l[i]; }
    return o;
}

// I/O: points come in as Jacobian (24 u32: x||y||z) in lefts/rights; affine out (16 u32).
fn load_pt_l(node: u32) -> Pt {
    var p: Pt; let b = node * 24u;
    for (var i = 0u; i < 8u; i = i + 1u) { p.x.l[i] = lefts[b + i]; p.y.l[i] = lefts[b + 8u + i]; p.z.l[i] = lefts[b + 16u + i]; }
    return p;
}
fn load_pt_r(node: u32) -> Pt {
    var p: Pt; let b = node * 24u;
    for (var i = 0u; i < 8u; i = i + 1u) { p.x.l[i] = rights[b + i]; p.y.l[i] = rights[b + 8u + i]; p.z.l[i] = rights[b + 16u + i]; }
    return p;
}
fn store_affine(node: u32, a: array<u32, 16>) { let b = node * 16u; for (var i = 0u; i < 16u; i = i + 1u) { outp[b + i] = a[i]; } }

@compute @workgroup_size(64)
fn point_add(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x; let n = arrayLength(&outp) / 16u; if (node >= n) { return; }
    store_affine(node, pt_to_affine(pt_add(load_pt_l(node), load_pt_r(node))));
}

@compute @workgroup_size(64)
fn point_double(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x; let n = arrayLength(&outp) / 16u; if (node >= n) { return; }
    if (arrayLength(&rights) == 0u) { return; } // keep binding 1 in the auto layout (host binds a dummy)
    store_affine(node, pt_to_affine(pt_double(load_pt_l(node))));
}
