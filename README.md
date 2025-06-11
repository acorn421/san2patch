# San2Patch

**Logs In, Patches Out: Automated Vulnerability Repair via Tree-of-Thought LLM Analysis**

This repository contains the code for our USENIX Security 2025 paper, San2Patch.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start-recommended)
- [Alternative Installation](#alternative-installation)
- [Configuration](#configuration)
- [Dataset Setup](#dataset-setup)
- [Usage](#usage)
- [Results](#results)
- [Experiment Scripts](#experiment-scripts)
- [Experiment Tracking](#experiment-tracking)
- [Code Structure](#code-structure)

## Prerequisites

### Common
- **Docker**: Version 28.0.0+
- **LLM API Keys**: At least one of OpenAI, Anthropic, or Google API keys
- **LangSmith API Key**: Optional, but recommended for experiment tracking

### Local Installation
- **Python**: Version 3.10
- **Poetry**: Version 2+

## Quick Start

### Using Pre-built Docker Images (Highly Recommended)

1. **Pull and run the pre-built images:**
   ```bash
   docker pull acorn421/san2patch
   # This can be slow cause it pulls the benchmark container
   docker run -it --privileged --name san2patch acorn421/san2patch
   ```

2. **Setup env variables (inside the container)**
    ```bash
    # Edit .env file with your API keys (see Configuration section)
    vim .env
    ```

3. **Run a quick test (inside the container)**
   ```bash
   # Test with a single vulnerability
   python ./run.py Final run-patch --vuln-ids "CVE-2016-1839" --model "gpt-4o" --experiment-name "test_experiment"
   ```

4. **Check the results**
   ```bash
   # Check the results (see Results section)
   cd ./benchmarks/final/final-test/gen_diff_test_experiment
   ```

### About Docker Image

The `acorn421/san2patch` Docker image uses Docker-in-Docker to run the `acorn421/san2patch-benchmark` Docker container internally for conducting experiments.

The Docker environment automatically provides:
- **San2Patch Dependencies and Packages**: Complete Python environment with all dependencies and san2patch code
- **Pre-generated Dataset**: Pre-generated data referenced from the host (dind base container) (e.g., sanitizer log, repo code, vulnerability info, etc.)
- **Pre-built Benchmark Container**: `acorn421/san2patch-benchmark` docker container with pre-configured San2Patch benchmarks (VulnLoc + San2Vuln)
- **Aim Tracking Server**: For experiment monitoring at `http://localhost:43800`

## Alternative Installation

### Option 1: Build Docker Image Locally

```bash
./docker-build.sh
docker run -it --privileged --name san2patch acorn421/san2patch
```

### Option 2: Local Installation (Not Recommended)

```bash
# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies
poetry install

# Activate virtual environment
poetry shell

# You'll still need Docker for the benchmark container
docker pull acorn421/san2patch-benchmark
docker run -d --name san2patch-benchmark acorn421/san2patch-benchmark

# Setup env variables
cp .env_example .env
# Add your API keys
vim .env

# Test patch generation for specific vulnerabilities
python ./run.py Final run-patch \
    --vuln-ids "CVE-2016-1839" \
    --model "gpt-4o" \
    --experiment-name "test_experiment"

# Check the results (see Results section)
cd ./benchmarks/final/final-test/gen_diff_test_experiment
```

## Configuration

### Environment Variables

Copy `.env_example` to `.env` and configure the following:

```bash
# Required: LLM API Keys (at least one)
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here  
GOOGLE_API_KEY=your_google_api_key_here

# Dataset directories (usually defaults are fine)
DATASET_DOWNLOAD_DIR=./benchmarks/download
DATASET_EXTRACTED_DIR=./benchmarks/extracted
DATASET_PREPROCESSED_DIR=./benchmarks/preprocessed
DATASET_FINAL_DIR=./benchmarks/final
DATASET_TEST_DIR=./benchmarks/final/final-test

# Optional: Experiment tracking (Recommended)
# LangSmith is recommended for experiment tracking due to its cost-effectiveness and user-friendly interface.
# Note that the framework's stability and functionality without LangSmith integration has not been extensively validated.
# See https://docs.smith.langchain.com/administration/how_to_guides/organization_management/create_account_api_key for how to get the API key
LANGCHAIN_TRACING_V2=true  # Set to true to enable LangSmith
LANGSMITH_API_KEY=your_langsmith_key
LANGCHAIN_PROJECT=San2Patch

# Aim server configuration (usually defaults are fine)
AIM_SERVER_URL=aim://localhost:53800
AIM_ARTIFACTS_URI=file:///app/.aim
```



## Dataset Setup

The term "Dataset" refers to the benchmark data prepared in the host environment.

For Patch Generation, the dataset is pre-built and prepared on the host system, rather than inside the   `san2patch-benchmark` container.

For Patch Validation, the process is performed inside the `san2patch-benchmark` container.

### Use Dataset inside the container (Recommended)

**The provided Docker image `acorn421/san2patch` already contains the pre-built dataset**, so no additional setup is required. This is the recommended approach for artifact evaluation as it ensures consistency and saves setup time.

```bash
# After running the container, the dataset is immediately available at:
# /app/benchmarks/final/final-test/

# You can directly run experiments without any dataset setup:
python ./run.py Final run-patch --vuln-ids "CVE-2016-1839" --model "gpt-4o"

# Or run the paper experiments:
./experiments/rq1/tot_vulnloc.sh
```

### Dataset Setup from Scratch

The `prepare_san2patch_benchmark.sh` script automatically downloads and prepares the San2Patch benchmark from the `san2patch-benchmark` container:

```bash
# If using Docker
docker exec -it san2patch bash
./scripts/prepare_san2patch_benchmark.sh

# If using local installation
poetry shell
./scripts/prepare_san2patch_benchmark.sh
```

**Note**: Some repos contain symbolic links in the docker image, which need to be manually handled. So we recommend using the pre-built docker image.

### Dataset Structure

After setup, your dataset will be organized as:

```
benchmarks/
├── final/
│   └── final-test/
│       ├── vuln/                          # Vulnerability metadata
│       ├── sanitizer/                     # Sanitizer outputs
│       ├── patch/                         # Ground truth patches
│       ├── repo/                          # Source code repositories (for code context)
│       ├── repo_copy/                     # Source code repositories (for diff generation)
│       └── gen_diff_{experiment_name}/    # Results of each experiment
```

## Usage

### Command Reference (run.py)

```bash
python ./run.py Final run-patch --help

Usage: run.py [[Final]] run-patch [OPTIONS] [NUM_WORKERS]

Options:
  --experiment-name TEXT          Experiment name. If not provided, the
                                  experiment name will be automatically
                                  generated by the current date and time.
  --retry-cnt INTEGER             Number of retries
  --max-retry-cnt INTEGER         Maximum number of retries for accumulative
                                  experiments. If 0, it will retry
                                  indefinitely until retry-cnt is reached
  --model [gpt-4o|gpt-4o-mini|gpt-3.5|claude-3.5-sonnet|claude-3-haiku|claude-3-opus|gemini-1.5-pro|gemini-1.5-flash]
                                  Model name to run
  --version [tot|no_context|cot|zeroshot|no_comprehend|no_howtofix]
                                  Prompting version
  --docker-id TEXT                Docker ID to run. If not provided, the
                                  docker id will be automatically detected by
                                  the name of the container (san2patch-
                                  benchmark).
  --vuln-ids TEXT                 Comma separated list of vuln_ids to run, or
                                  group of vuln_ids (san2vuln, vulnloc). If
                                  not provided, all vuln_ids will be run.
  --select-method TEXT            Select method for ToT (sample, greedy)
  --temperature-setting TEXT      Temperature setting
  --raise-exception               Raise exception
  --help                          Show this message and exit.
```

- `NUM_WORKERS`: Number of parallel workers (optional positional argument, default: 1)
- **version**: Prompting version
   - **tot**: Tree-of-Thought approach of original paper (default)
   - **no-context**: Without code context analysis
   - **no-comprehend**: Without comprehension step
   - **no-howtofix**: Without how-to-fix reasoning
   - **cot**: Chain-of-thought baseline
   - **zeroshot**: Zero-shot baseline
- **model**: Supported LLM Models
   - **OpenAI**: `gpt-4o`, `gpt-4o-mini`, `gpt-3.5`
   - **Anthropic**: `claude-3.5-sonnet`, `claude-3-haiku`, `claude-3-opus`
   - **Google**: `gemini-1.5-pro`, `gemini-1.5-flash`

## Results

After running experiments, San2Patch generates results in the `gen_diff_<experiment_name>` directories under `/app/benchmarks/final/final-test/`. Here's how to interpret the results structure:

### Generated Results Directory Structure

```
benchmarks/final/final-test/
├── gen_diff_<experiment_name>/          # Results for specific experiment
│   ├── <vuln_id>/                      # Individual vulnerability results
│   │   ├── res.txt                     # Execution summary and status
│   │   ├── <experiment>_<vuln_id>_success.diff    # Final successful patch (if patch success)
│   │   ├── <experiment>_<vuln_id>_success.artifact # Final successful langgraph debugging artifacts (if patch success)
│   │   └── stage_0_<stage_id>/        # Detailed stage results
│   │       ├── <vuln_id>.diff          # Final generated patch
│   │       ├── <vuln_id>_<variant>.diff # Patch candidates
│   │       ├── <vuln_id>.vuln.out      # Final vulnerability test output
│   │       └── <vuln_id>_graph_output.json # Debugging files from langgraph (for debugging)
│   └── ...
```

### Understanding the Results

**Main Result Files:**
- `res.txt` - Summary of all attempts with status codes and LangSmith trace URLs
- `*_success.diff` - The final patch that passed all automated tests (vulnerability test and functionality test)
- `*_success.artifact` - Complete execution trace and intermediate outputs

**Stage Directories:**
- `stage_0_<stage_id>/` - Results from specific retry attempts and reasoning stages
- `*.diff` files - Generated patch candidates from the reasoning process
- `*.vuln.out` - Vulnerability testing output to verify patch correctness
- `*_graph_output.json` - Complete state of LangGraph reasoning process for debugging

**Status Codes in res.txt:**
- `success` - Patch generated and passed all tests
- `build_failed` - Generated patch caused compilation errors
- `vuln_test_failed` - Patch generated and compiled successfully, but failed vulnerability test
- `func_test_failed` - Patch compiled successfully, passed vulnerability test, but failed functionality test


### Example: Checking Results

```bash
# Navigate to experiment results
cd /app/benchmarks/final/final-test/gen_diff_my_experiment

# Check overall results
ls ./**/res.txt | xargs -I {} bash -c "echo '===== {} ===='; cat {}; echo;"

# Count successful patches
ls ./**/res.txt | xargs -I {} bash -c "echo '===== {} ===='; cat {}; echo;" | grep "success" | wc -l
```

## Experiment Scripts

The experiment scripts are located in the `experiments` directory and contain the exact commands used for evaluation in our USENIX Security 2025 paper.

### Research Questions Evaluation

**RQ1: Superiority of San2Patch**
- `experiments/rq1/tot_vulnloc.sh` - Tree-of-Thought approach on VulnLoc dataset
- `experiments/rq1/cot_vulnloc.sh` - Chain-of-Thought baseline comparison  
- `experiments/rq1/no_context_vulnloc.sh` - No context baseline
- `experiments/rq1/zeroshot_vulnloc.sh` - Zero-shot baseline

**RQ2: Effectiveness on New Vulnerabilities**
- `experiments/rq2/tot_san2vuln.sh` - Tree-of-Thought on San2Vuln dataset

**RQ3: Impact of LLM Models**
- `experiments/rq3/gpt_4o_mini.sh` - GPT-4o-mini evaluation
- `experiments/rq3/gpt_35.sh` - GPT-3.5 evaluation
- `experiments/rq3/sonnet_35.sh` - Claude-3.5-Sonnet evaluation
- `experiments/rq3/gemini_15_pro.sh` - Gemini-1.5-Pro evaluation
- `experiments/rq3/gemini_15_flash.sh` - Gemini-1.5-Flash evaluation

**Ablation Studies (in Appendix)**
- `experiments/ablation/no_comprehend_k5.sh` - Without comprehension step
- `experiments/ablation/no_howtofix_k5.sh` - Without how-to-fix reasoning

### Running Paper Experiments

To reproduce the exact results from our paper:

```bash
# Inside the container, run specific research question
cd /app

# RQ1: Superiority of San2Patch
./experiments/rq1/tot_vulnloc.sh
./experiments/rq1/cot_vulnloc.sh
./experiments/rq1/no_context_vulnloc.sh
./experiments/rq1/zeroshot_vulnloc.sh

# RQ2: Effectiveness on New Vulnerabilities
./experiments/rq2/tot_san2vuln.sh

# RQ3: Impact of LLM Models  
./experiments/rq3/gpt_4o_mini.sh
./experiments/rq3/gpt_35.sh
./experiments/rq3/sonnet_35.sh
./experiments/rq3/gemini_15_pro.sh
./experiments/rq3/gemini_15_flash.sh

# Ablation Studies (in Appendix)
./experiments/ablation/no_comprehend_k5.sh
./experiments/ablation/no_howtofix_k5.sh
```

**Note**: If you are using multiple benchmark containers, update the `--docker-id` parameter in each script to match your benchmark container ID before running. Otherwise, the script will automatically find the container ID from the `docker ps` command named `san2patch-benchmark`.

## Experiment Tracking

### Aim Server

San2Patch includes integrated experiment tracking using Aim:

```bash
# Aim server starts automatically with Docker container
# Access the web UI at: http://localhost:43800

# Or start manually:
./scripts/start_aim.sh
```

### LangSmith Integration (Optional, but recommended)

For detailed LLM call tracing:

1. Set up LangSmith account at https://smith.langchain.com
2. Configure environment variables:
   ```bash
   LANGCHAIN_TRACING_V2=true
   LANGSMITH_API_KEY=your_api_key
   LANGCHAIN_PROJECT=San2Patch
   ```
3. Check the LangSmith tracing url in `res.txt` file.

## Code Structure

```
san2patch/
├── san2patch/             # Core San2Patch package
│   ├── patching/          # Core patching logic
│   ├── dataset/           # Dataset handling
│   ├── utils/             # Utilities (Docker, commands, etc.)
│   ├── context.py         # Context management
│   ├── consts.py          # Constants
│   └── types.py           # Types
├── scripts/               # Utility scripts
├── benchmarks/            # Dataset storage
├── experiments/           # Experiment scripts of original paper
└── run.py                 # Main entry point
```
