// sinsemilla.wgsl — Sinsemilla hash_to_point. Requires field.wgsl + pallas.wgsl.
// Generator table at binding 3: Q at index 0, S[m] at index m+1, each affine x||y (16 u32).
// Recurrence (SINSEMILLA-SPEC §5): acc = Q; per 10-bit chunk value m: acc = (acc + S[m]) + acc.

@group(0) @binding(3) var<storage, read> gens: array<u32>;

fn gen_pt(idx: u32) -> Pt {
    var p: Pt;
    let b = idx * 16u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        p.x.l[i] = gens[b + i];
        p.y.l[i] = gens[b + 8u + i];
    }
    p.z = fp_one();
    return p;
}

// hash_to_point over `nchunks` chunk values read from `lefts` starting at `base`.
fn hash_chunks_at(base: u32, nchunks: u32) -> Pt {
    var acc = gen_pt(0u); // Q
    for (var c = 0u; c < nchunks; c = c + 1u) {
        let m = lefts[base + c]; // chunk value 0..1023
        acc = pt_add(pt_add(acc, gen_pt(1u + m)), acc);
    }
    return acc;
}

// MerkleCRH message = 10 + 255 + 255 = 520 bits = 52 * K chunks.
const SINSEMILLA_NCHUNKS: u32 = 52u;

// S3 entry: one message = SINSEMILLA_NCHUNKS chunk values in `lefts`; output affine x (8 u32).
@compute @workgroup_size(64)
fn hash_chunks(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x;
    let n = arrayLength(&outp) / 8u;
    if (node >= n) { return; }
    let acc = hash_chunks_at(node * SINSEMILLA_NCHUNKS, SINSEMILLA_NCHUNKS);
    let xy = pt_to_affine(acc); // (x || y)
    let b = node * 8u;
    for (var i = 0u; i < 8u; i = i + 1u) { outp[b + i] = xy[i]; } // store x = extract_p
}

// ---- S4: MerkleCRH combine — encode (layer, left, right) then hash ----
// message bit j (SINSEMILLA-SPEC §8): [0,10)=layer LE, [10,265)=left low-255 LE,
// [265,520)=right low-255 LE.
fn msg_bit(layer: u32, left: Fp, right: Fp, j: u32) -> u32 {
    if (j < 10u) { return (layer >> j) & 1u; }
    if (j < 265u) { let b = j - 10u; return (left.l[b / 32u] >> (b % 32u)) & 1u; }
    let b = j - 265u; return (right.l[b / 32u] >> (b % 32u)) & 1u;
}
fn chunk_val(layer: u32, left: Fp, right: Fp, c: u32) -> u32 {
    var v = 0u;
    for (var k = 0u; k < 10u; k = k + 1u) {
        v = v | (msg_bit(layer, left, right, c * 10u + k) << k); // lebs2ip_k, LE
    }
    return v;
}

// input per element: layer (1 u32) || left (8 u32) || right (8 u32) = 17 u32. Output x (8 u32).
@compute @workgroup_size(64)
fn merkle_combine(@builtin(global_invocation_id) gid: vec3<u32>) {
    let node = gid.x;
    let n = arrayLength(&outp) / 8u;
    if (node >= n) { return; }
    let base = node * 17u;
    let layer = lefts[base];
    var left: Fp;
    var right: Fp;
    for (var i = 0u; i < 8u; i = i + 1u) {
        left.l[i] = lefts[base + 1u + i];
        right.l[i] = lefts[base + 9u + i];
    }
    var acc = gen_pt(0u); // Q
    for (var c = 0u; c < SINSEMILLA_NCHUNKS; c = c + 1u) {
        acc = pt_add(pt_add(acc, gen_pt(1u + chunk_val(layer, left, right, c))), acc);
    }
    let xy = pt_to_affine(acc);
    let b = node * 8u;
    for (var i = 0u; i < 8u; i = i + 1u) { outp[b + i] = xy[i]; } // store x
}
