# !/bin/bash

set -x

python ./scripts/run_dataset.py San2Patch all 
python ./scripts/run_dataset.py FinalTest aggregate