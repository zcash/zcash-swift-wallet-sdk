// v0.4 P0 bench-ios host (spec §3.4): the on-device measuring instrument.
// One screen → one probe call → the engine's BenchSummary rendered as rows.
// Zodl is deliberately NOT the instrument (scope decision C, 2026-07-04).

import SwiftUI

@main
struct BenchApp: App {
    var body: some Scene {
        WindowGroup { BenchView() }
    }
}

struct BenchView: View {
    @State private var server = "https://zec.rocks:443"
    @State private var ufvk = ""
    @State private var birthday = "3105000"
    @State private var graft = true
    @State private var batch = true
    @State private var batchDecrypt = false
    @State private var running = false
    @State private var verdict: String?
    @State private var rows: [(String, String)] = []

    var body: some View {
        NavigationStack {
            Form {
                Section("Reference wallet") {
                    TextField("lightwalletd URL", text: $server)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("UFVK (uview1…)", text: $ufvk, axis: .vertical)
                        .lineLimit(3)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("Birthday height", text: $birthday)
                        .keyboardType(.numberPad)
                }
                Section("v0.4 levers (ON by default since 0.4.0)") {
                    Toggle("Graft subtree roots (Plan A)", isOn: $graft)
                    Toggle("Batch-affine Sinsemilla (Plan B)", isOn: $batch)
                }
                Section("v0.5 levers") {
                    Toggle("Batched trial-decrypt DH (C1)", isOn: $batchDecrypt)
                }
                Section {
                    Button {
                        run()
                    } label: {
                        if running {
                            HStack {
                                ProgressView()
                                Text("Restoring… keep the app open")
                            }
                        } else {
                            Text("Run fresh-restore bench")
                        }
                    }
                    .disabled(running || ufvk.isEmpty || UInt32(birthday) == nil)
                }
                if let verdict {
                    Section("Result") { Text(verdict).font(.footnote.monospaced()) }
                }
                if !rows.isEmpty {
                    Section("BenchSummary") {
                        ForEach(rows, id: \.0) { row in
                            LabeledContent(row.0, value: row.1)
                                .font(.footnote.monospaced())
                        }
                    }
                }
            }
            .navigationTitle("Slipstream Bench")
        }
    }

    private func run() {
        guard let height = UInt32(birthday) else { return }
        running = true
        verdict = nil
        rows = []
        let server = server
        let ufvk = ufvk
        let graft = graft
        let batch = batch
        let batchDecrypt = batchDecrypt
        Task.detached(priority: .userInitiated) {
            // Fresh subdir per run — the probe refuses a dirty wallet dir.
            let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("bench-\(UUID().uuidString.prefix(8))", isDirectory: true)
            var buf = [CChar](repeating: 0, count: 64 * 1024)
            let rc = slipstream_bench_run(server, ufvk, height, dir.path, false, graft, batch, batchDecrypt, &buf, buf.count)
            let json = rc == 0 ? String(cString: buf) : nil
            await MainActor.run {
                running = false
                if let json {
                    verdict = "OK (graft=\(graft ? "on" : "off") batch=\(batch ? "on" : "off") decrypt=\(batchDecrypt ? "on" : "off")) — json also at \(dir.path)/bench.json"
                    rows = Self.flatten(json: json)
                } else {
                    verdict = "failed: probe rc \(rc) (see Xcode console for engine logs)"
                }
            }
        }
    }

    /// BenchSummary is one flat object + two pool objects — render every leaf as a row.
    static func flatten(json: String) -> [(String, String)] {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return [("json", "unparseable")] }
        var out: [(String, String)] = []
        for key in obj.keys.sorted() {
            if let pool = obj[key] as? [String: Any] {
                for sub in pool.keys.sorted() {
                    out.append(("\(key).\(sub)", "\(pool[sub] ?? "")"))
                }
            } else {
                out.append((key, "\(obj[key] ?? "")"))
            }
        }
        return out
    }
}
