#!/usr/bin/env bash

# Fetch standard evaluation datasets for SIFT
set -e

# create datasets folder if not exists
mkdir -p datasets
cd datasets

# OpenSSF CVE Benchmark
if [ ! -d "ossf-cve-benchmark" ]; then
    echo "Cloning OpenSSF CVE Benchmark..."
    git clone https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git
else
    echo "OpenSSF CVE Benchmark already present, pulling latest..."
    cd ossf-cve-benchmark && git pull && cd ..
fi

# A.S.E Benchmark (this is hypothetical URL; adjust as needed)
if [ ! -d "ase-benchmark" ]; then
    echo "Cloning A.S.E Benchmark..."
    git clone https://github.com/Tencent/AICGSecEval.git || \
        echo "Please update the URL for the A.S.E benchmark repository."
else
    echo "A.S.E Benchmark already present, pulling latest..."
    cd ase-benchmark && git pull && cd ..
fi

echo "Datasets are ready under $(pwd)"