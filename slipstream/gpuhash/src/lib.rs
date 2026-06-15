//! `slipstream-gpuhash` — GPU-accelerated Orchard Sinsemilla MerkleCRH `combine`.
//!
//! Graduated verbatim from the Phase A spike (`zcash-gpu-spike/crates/gpu-wgpu`), which proved
//! the WGSL kernels bit-exact vs `orchard::tree::MerkleHashOrchard::combine` (oracle 0/10M).
//! The shaders (`field.wgsl` + `pallas.wgsl` + `sinsemilla.wgsl`) are unchanged. Public entry
//! point: [`orchard_combine_batch`]. Used ONLY behind `slipstream-core`'s `gpu` feature.
//!
//! Note: the GPU-infrastructure `unwrap`s in `dispatch_hash` (device poll / buffer map) are a
//! documented B0 exception to the no-unwrap convention — a GPU device failure is unrecoverable
//! for the offload path, and correctness is covered by the engine's CPU fallback
//! (`gpu_subtree=false` and `GpuHashOrchard::combine`'s per-node fallback). B1 productization
//! converts these to `Result`.

use std::sync::OnceLock;
use wgpu::util::DeviceExt;

use ff::PrimeField;
use group::Curve;
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;

/// Bit-exact WGSL kernels (Phase A). Concatenated by the host into one shader module.
pub const FIELD_WGSL: &str = include_str!("../shaders/field.wgsl");
pub const PALLAS_WGSL: &str = include_str!("../shaders/pallas.wgsl");
pub const SINSEMILLA_WGSL: &str = include_str!("../shaders/sinsemilla.wgsl");

/// A live, reusable GPU context (adapter + device + queue). Send + Sync.
pub struct Gpu {
    pub device: wgpu::Device,
    pub queue: wgpu::Queue,
    pub info: wgpu::AdapterInfo,
}

impl Gpu {
    /// Pick the highest-performance adapter present and open a device.
    pub fn new() -> Self {
        pollster::block_on(Self::new_async())
    }

    async fn new_async() -> Self {
        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .expect("no GPU adapter found");
        let info = adapter.get_info();
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("slipstream-gpuhash"),
                required_features: wgpu::Features::empty(),
                // Request exactly what THIS adapter supports (older mobile GPUs like the A10
                // don't meet every desktop default limit; the adapter's own limits always
                // succeed and are ample for 3 storage buffers + a 64-wide workgroup).
                required_limits: adapter.limits(),
                memory_hints: wgpu::MemoryHints::Performance,
                trace: wgpu::Trace::Off,
                ..Default::default()
            })
            .await
            .expect("failed to open GPU device");
        Self { device, queue, info }
    }

    /// Dispatch a Sinsemilla hash kernel: input at binding 0, output (8 u32/element) at
    /// binding 2, generator table at binding 3. Single dispatch (Mac/CLI; device-side
    /// watchdog chunking is a B1 concern).
    fn dispatch_hash(
        &self,
        shader_src: &str,
        entry: &str,
        input: &[u32],
        gens: &[u32],
        out_u32_len: usize,
    ) -> Vec<u32> {
        let in_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("hash-in"),
            contents: bytemuck::cast_slice(input),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let gen_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("hash-gens"),
            contents: bytemuck::cast_slice(gens),
            usage: wgpu::BufferUsages::STORAGE,
        });
        let size = (out_u32_len * std::mem::size_of::<u32>()) as wgpu::BufferAddress;
        let out_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("hash-out"),
            size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("hash-staging"),
            size,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let shader = self.device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some(entry),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });
        let pipeline = self
            .device
            .create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some(entry),
                layout: None,
                module: &shader,
                entry_point: Some(entry),
                compilation_options: Default::default(),
                cache: None,
            });
        let layout = pipeline.get_bind_group_layout(0);
        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("hash-bg"),
            layout: &layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: in_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 2, resource: out_buf.as_entire_binding() },
                wgpu::BindGroupEntry { binding: 3, resource: gen_buf.as_entire_binding() },
            ],
        });
        let n_elems = (out_u32_len / 8) as u32;
        let mut enc = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        {
            let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some(entry),
                timestamp_writes: None,
            });
            pass.set_pipeline(&pipeline);
            pass.set_bind_group(0, &bind, &[]);
            pass.dispatch_workgroups(n_elems.div_ceil(64).max(1), 1, 1);
        }
        enc.copy_buffer_to_buffer(&out_buf, 0, &staging, 0, size);
        self.queue.submit(Some(enc.finish()));
        let slice = staging.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        self.device
            .poll(wgpu::PollType::Wait { submission_index: None, timeout: None })
            .unwrap();
        rx.recv().unwrap().unwrap();
        let data = slice.get_mapped_range();
        let out: Vec<u32> = bytemuck::cast_slice(&data).to_vec();
        drop(data);
        staging.unmap();
        out
    }

    /// GPU MerkleCRH `combine` of `n` elements. `input`: n×17 u32 (layer ‖ left8 ‖ right8).
    /// Returns n×8 u32 (the combine output x). `gens` = the generator table.
    pub fn merkle_combine(&self, input: &[u32], gens: &[u32], n: usize) -> Vec<u32> {
        let src = format!("{FIELD_WGSL}\n{PALLAS_WGSL}\n{SINSEMILLA_WGSL}");
        self.dispatch_hash(&src, "merkle_combine", input, gens, n * 8)
    }
}

/// Process-global device (wgpu Device/Queue are Send+Sync). Created once on first use.
fn shared() -> &'static Gpu {
    static GPU: OnceLock<Gpu> = OnceLock::new();
    GPU.get_or_init(Gpu::new)
}

/// Generator table as u32 LE: Q at index 0, then `SINSEMILLA_S[0..1024]`, each affine x‖y
/// (16 u32). Consensus-fixed; computed once. Q = `hash_to_curve("z.cash:SinsemillaQ")` of the
/// Orchard MerkleCRH domain (`sinsemilla` lib.rs:139); S = the crate's precomputed table.
fn generators_u32() -> &'static [u32] {
    static GENS: OnceLock<Vec<u32>> = OnceLock::new();
    GENS.get_or_init(|| {
        fn affine_xy(p: pallas::Point) -> [u8; 64] {
            let bytes: Option<[u8; 64]> = p
                .to_affine()
                .coordinates()
                .map(|c| {
                    let mut o = [0u8; 64];
                    o[..32].copy_from_slice(&c.x().to_repr());
                    o[32..].copy_from_slice(&c.y().to_repr());
                    o
                })
                .into();
            bytes.expect("Sinsemilla generator is non-identity (consensus constant)")
        }
        let q = pallas::Point::hash_to_curve("z.cash:SinsemillaQ")("z.cash:Orchard-MerkleCRH".as_bytes());
        let mut bytes: Vec<u8> = Vec::with_capacity(64 * (1 + (1 << 10)));
        bytes.extend_from_slice(&affine_xy(q));
        for m in 0..(1usize << 10) {
            let (x, y) = sinsemilla::SINSEMILLA_S[m];
            bytes.extend_from_slice(&x.to_repr());
            bytes.extend_from_slice(&y.to_repr());
        }
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    })
}

/// Batched Orchard MerkleCRH `combine`. `layers[i]`/`lefts[i]`/`rights[i]` → `output[i]`,
/// each 32 canonical bytes, byte-identical to `MerkleHashOrchard::combine(Level::from(layer),
/// &left, &right)`. Inputs are canonical 32-byte field elements.
pub fn orchard_combine_batch(
    layers: &[u8],
    lefts: &[[u8; 32]],
    rights: &[[u8; 32]],
) -> Vec<[u8; 32]> {
    assert_eq!(layers.len(), lefts.len(), "layers/lefts length mismatch");
    assert_eq!(layers.len(), rights.len(), "layers/rights length mismatch");
    let n = layers.len();
    if n == 0 {
        return Vec::new();
    }
    let mut input = Vec::with_capacity(n * 17);
    for i in 0..n {
        input.push(layers[i] as u32);
        for w in 0..8 {
            input.push(u32::from_le_bytes([
                lefts[i][4 * w], lefts[i][4 * w + 1], lefts[i][4 * w + 2], lefts[i][4 * w + 3],
            ]));
        }
        for w in 0..8 {
            input.push(u32::from_le_bytes([
                rights[i][4 * w], rights[i][4 * w + 1], rights[i][4 * w + 2], rights[i][4 * w + 3],
            ]));
        }
    }
    let out = shared().merkle_combine(&input, generators_u32(), n);
    (0..n)
        .map(|i| {
            let mut b = [0u8; 32];
            for w in 0..8 {
                b[4 * w..4 * w + 4].copy_from_slice(&out[i * 8 + w].to_le_bytes());
            }
            b
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use incrementalmerkletree::{Hashable, Level};
    use orchard::tree::MerkleHashOrchard;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn orchard_combine_batch_matches_orchard() {
        let mut rng = StdRng::seed_from_u64(0xB0_1);
        let n = 10_000;
        // deterministic valid nodes: fold combine from empties
        let mut pool = Vec::with_capacity(2 * n);
        let mut a = MerkleHashOrchard::empty_leaf();
        let mut b = MerkleHashOrchard::empty_root(Level::from(0));
        for _ in 0..2 * n {
            let c = MerkleHashOrchard::combine(Level::from(0), &a, &b);
            pool.push(c);
            a = b;
            b = c;
        }
        let layers: Vec<u8> = (0..n).map(|_| (rng.next_u32() % 32) as u8).collect();
        let lefts: Vec<[u8; 32]> = (0..n).map(|i| pool[i].to_bytes()).collect();
        let rights: Vec<[u8; 32]> = (0..n).map(|i| pool[n + i].to_bytes()).collect();

        let got = orchard_combine_batch(&layers, &lefts, &rights);

        for i in 0..n {
            let exp = MerkleHashOrchard::combine(
                Level::from(layers[i]),
                &Option::from(MerkleHashOrchard::from_bytes(&lefts[i])).expect("canonical"),
                &Option::from(MerkleHashOrchard::from_bytes(&rights[i])).expect("canonical"),
            )
            .to_bytes();
            assert_eq!(got[i], exp, "mismatch at {i}");
        }
    }
}
