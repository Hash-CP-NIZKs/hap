// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use demo::TestCase;

fn criterion_benchmark(c: &mut Criterion) {
    env_logger::builder().is_test(true).try_init().unwrap();

    let mut group = c.benchmark_group("Proof creation");
    group
        .sample_size(10)
        .sampling_mode(criterion::SamplingMode::Flat); // for slow benchmarks

    // setup
    let urs = demo::api::setup(1000, 1000, 1000);

    // We run 64 times for each batch
    let batch_num = 64;

    let test_case = TestCase::Test1;
    let circuit_keys = demo::api::compile(test_case, &urs);

    group.bench_function("small message", |b| {
        b.iter(|| {
            // prove all tuples
            demo::prove_and_verify(test_case, &urs, &circuit_keys, black_box(batch_num));
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
