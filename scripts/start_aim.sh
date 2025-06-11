# Start AIM stack using Docker run in background
docker run -d \
  --name aimstack \
  -p 53800:53800 \
  aimstack/aim server > /dev/null 2>&1

# Wait a moment for the service to start
sleep 5

# Start aim up in background with -y flag and artifacts URI
if [ -n "${AIM_ARTIFACTS_URI}" ]; then
    aim up --repo "${AIM_ARTIFACTS_URI}" -y > /dev/null 2>&1 &
else
    echo "Error: AIM_ARTIFACTS_URI environment variable is not set"
    exit 1
fi

echo "Both services started in background!"
echo "Docker container logs: docker logs -f aimstack"
echo "AIM UI should be available at: http://localhost:43800"