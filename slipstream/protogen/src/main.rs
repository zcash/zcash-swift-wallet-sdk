//! Regenerates the darkside-control gRPC client into slipstream-core.
//! Shared walletrpc types are extern-mapped to zcash_client_backend's
//! generated module so no duplicate prost types exist.

fn main() -> anyhow::Result<()> {
    let out = std::path::Path::new("slipstream/core/src/grpc_generated");
    std::fs::create_dir_all(out)?;
    tonic_prost_build::configure()
        .build_server(false)
        .out_dir(out)
        .extern_path(
            ".cash.z.wallet.sdk.rpc.Empty",
            "::zcash_client_backend::proto::service::Empty",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.RawTransaction",
            "::zcash_client_backend::proto::service::RawTransaction",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.TreeState",
            "::zcash_client_backend::proto::service::TreeState",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.BlockID",
            "::zcash_client_backend::proto::service::BlockId",
        )
        .extern_path(
            ".cash.z.wallet.sdk.rpc.GetAddressUtxosReply",
            "::zcash_client_backend::proto::service::GetAddressUtxosReply",
        )
        .compile_protos(
            &["Tests/TestUtils/proto/darkside.proto"],
            &[
                "Tests/TestUtils/proto",
                "Sources/ZcashLightClientKit/Modules/Service/GRPC/ProtoBuf/proto",
            ],
        )?;
    Ok(())
}
