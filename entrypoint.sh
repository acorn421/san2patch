#!/bin/bash

# Function to load environment variables
load_environment() {
    echo "Starting: Loading environment variables..."
    source .env
    echo "Finished: Loading environment variables"
}

# Function to start Docker
start_docker() {
    echo "Starting: Starting Docker..."
    start-docker.sh
    echo "Finished: Starting Docker"
}

# Function to start AIM stack
start_aim_stack() {
    echo "Starting: Starting AIM stack..."
    export AIM_ARTIFACTS_URI="file:///app/.aim"
    bash ./scripts/start_aim.sh
    echo "Finished: Starting AIM stack"
}

# Function to run san2patch-benchmark container
start_benchmark_container() {
    echo "Starting: Running san2patch-benchmark docker container..."
    docker run -t -d \
        --name san2patch-benchmark \
        acorn421/san2patch-benchmark:latest
    echo "Finished: Running san2patch-benchmark docker container"
}

# Main execution flow
main() {
    echo "=== San2Patch Entrypoint Script Started ==="
    
    load_environment
    start_docker
    start_aim_stack
    start_benchmark_container
    
    echo "=== All initialization completed ==="
}

# Execute main function
main

exec "$@"