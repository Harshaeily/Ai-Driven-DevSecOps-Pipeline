#!/bin/bash
mkdir -p results
docker run --rm -v $(pwd)/results:/zap/results owasp/zap2docker-stable \
  zap-baseline.py -t $ZAP_TARGET -J /zap/results/zap.json