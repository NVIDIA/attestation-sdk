#!/bin/bash

set -euo pipefail

# --- Configuration ---
readonly IMAGE_NAME="nvattest-dev-image"
readonly CONTAINER_NAME="nv-attest-dev-container"

readonly PROJECT_ROOT="$(git rev-parse --show-toplevel)"
readonly MOUNT_TARGET_DIR="/attestation-sdk"
readonly DOCKERFILE_PATH="$PROJECT_ROOT/dev/Dockerfile"
cd "$PROJECT_ROOT"

# --- Helper Functions ---
usage() {
    echo "Usage: $0 {setup|start|stop|clean|status|shell}"
    echo "Manages the nv-attest development Docker environment."
    echo
    echo "Commands:"
    echo "  setup    Builds the Docker image '$IMAGE_NAME' and sets ownership"
    echo "           of '$PROJECT_ROOT' for user '$(whoami)' (requires sudo)."
    echo "  start    Starts the Docker container '$CONTAINER_NAME' in the background."
    echo "           If stopped, restarts the existing container."
    echo "  stop     Stops the running Docker container '$CONTAINER_NAME'."
    echo "  clean    Stops and removes the container '$CONTAINER_NAME',"
    echo "           then removes the image '$IMAGE_NAME'."
    echo "  status   Shows the status of the container '$CONTAINER_NAME'."
    echo "  shell    Executes an interactive bash shell in the running container."
    exit 1
}

# Check if container exists (running or stopped)
container_exists() {
    docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Check if container is currently running
container_is_running() {
    docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"
}

# Check if image exists
image_exists() {
    docker image inspect "$IMAGE_NAME" &> /dev/null
}

# --- Command Logic ---

# Check if Docker is installed and running
if ! command -v docker &> /dev/null || ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not installed or the Docker daemon is not running." >&2
    exit 1
fi

# Get the command, default to empty string if none provided
COMMAND=${1:-}

case "$COMMAND" in
    setup)
        echo "--- Setting up Development Environment ---"

        echo "[1/2] Building Docker image '$IMAGE_NAME'..."
        echo "      Using Dockerfile: $DOCKERFILE_PATH"
        echo "      Build context: $PROJECT_ROOT"
        if docker build -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" --platform linux/amd64 "$PROJECT_ROOT"; then
            echo "      Image '$IMAGE_NAME' built successfully."
        else
            echo "Error: Docker image build failed." >&2
            exit 1
        fi

        echo "[2/2] Ensuring ownership of '$PROJECT_ROOT' for user '$(whoami)'..."
        echo "      This requires sudo permissions to change ownership."
        # Use id -gn to get the primary group name of the user
        if sudo chown -R "$(whoami):$(id -gn)" "$PROJECT_ROOT"; then
             echo "      Ownership set successfully."
        else
             echo "Error: Failed to set ownership on '$PROJECT_ROOT'." >&2
             echo "       Manual command: sudo chown -R \$(whoami):\$(id -gn) \"$PROJECT_ROOT\""
             # Decide if this is fatal. Let's make it non-fatal but warn.
             echo "Warning: Proceeding despite ownership error. Mounts might fail if permissions are incorrect."
        fi

        # echo "--- Setup Complete ---"
        ;;

    start)
        echo "--- Starting Development Container '$CONTAINER_NAME' ---"

        if ! image_exists; then
            echo "Error: Image '$IMAGE_NAME' not found. Please run '$0 setup' first." >&2
            exit 1
        fi

        if container_is_running; then
            echo "Container '$CONTAINER_NAME' is already running."
            docker ps --filter "name=^/${CONTAINER_NAME}$"
        elif container_exists; then
            echo "Found stopped container '$CONTAINER_NAME'. Starting it..."
            if docker start "$CONTAINER_NAME"; then
                echo "Container started successfully."
                docker ps --filter "name=^/${CONTAINER_NAME}$"
            else
                echo "Error: Failed to start existing container '$CONTAINER_NAME'." >&2
                exit 1
            fi
        else
            echo "Creating and starting new container '$CONTAINER_NAME' in detached mode..."
            # Use 'sleep infinity' to keep the container running in detached mode.
            # Users can attach with 'docker exec' or using the 'shell' command.
            if docker run -d --network host --privileged --platform linux/amd64 --name "$CONTAINER_NAME" \
                   -v "$PROJECT_ROOT:$MOUNT_TARGET_DIR" \
                   "$IMAGE_NAME" sleep infinity; then
                echo "Container started successfully."
                echo "Use '$0 shell' to get an interactive shell inside."
                docker ps --filter "name=^/${CONTAINER_NAME}$"
            else
                echo "Error: Failed to create and start container '$CONTAINER_NAME'." >&2
                exit 1
            fi
        fi
        echo "--- Start Complete ---"
         ;;

    stop)
        echo "--- Stopping Development Container '$CONTAINER_NAME' ---"
        if container_is_running; then
            echo "Stopping container '$CONTAINER_NAME'..."
            if docker stop "$CONTAINER_NAME"; then
                echo "Container stopped successfully."
            else
                echo "Error: Failed to stop container '$CONTAINER_NAME'." >&2
                # Don't exit, could be partially stopped or other issue.
            fi
        elif container_exists; then
            echo "Container '$CONTAINER_NAME' exists but is already stopped."
        else
            echo "Container '$CONTAINER_NAME' not found."
        fi
        echo "--- Stop Complete ---"
        ;;

    clean)
        echo "--- Cleaning Development Environment ---"

        # Stop and remove container
        if container_exists; then
            echo "[1/2] Stopping and removing container '$CONTAINER_NAME'..."
            # Use -f to force remove even if running, simplifies logic and handles stop+remove
            if docker rm -f "$CONTAINER_NAME"; then
                 echo "      Container removed successfully."
            else
                 echo "Error: Failed to remove container '$CONTAINER_NAME'." >&2
                 # Continue to image removal attempt anyway
            fi
        else
            echo "[1/2] Container '$CONTAINER_NAME' not found, skipping removal."
        fi

        # Remove image
        if image_exists; then
             echo "[2/2] Removing image '$IMAGE_NAME'..."
             if docker rmi "$IMAGE_NAME"; then
                 echo "      Image removed successfully."
             else
                 echo "Error: Failed to remove image '$IMAGE_NAME'. It might be in use by other (non-dev) containers or dependent images." >&2
                 # Don't exit
             fi
        else
             echo "[2/2] Image '$IMAGE_NAME' not found, skipping removal."
        fi

        echo "--- Clean Complete ---"
        ;;

    status)
        echo "--- Container Status '$CONTAINER_NAME' ---"
        if container_exists; then
            # Show details including port mappings, status, etc.
            docker ps -a --filter "name=^/${CONTAINER_NAME}$"
        else
            echo "Container '$CONTAINER_NAME' does not exist."
        fi
        if image_exists; then
            echo "Image '$IMAGE_NAME' exists."
            docker images "$IMAGE_NAME"
        else
             echo "Image '$IMAGE_NAME' does not exist."
        fi
        echo "--- Status Complete ---"
        ;;

    shell)
         echo "--- Attaching Shell to '$CONTAINER_NAME' ---"
         if ! container_is_running; then
             echo "Error: Container '$CONTAINER_NAME' is not running. Use '$0 start' first." >&2
             exit 1
         fi
         echo "Connecting to container... Type 'exit' to return."
         # Use exec to run bash in the *running* container
         docker exec --workdir "$MOUNT_TARGET_DIR" -it "$CONTAINER_NAME" bash
         echo "--- Shell Exited ---"
         ;;

    *) # Handle invalid command or no command
        usage
        ;;
esac

exit 0
