# lab-setup/ — Vulnerable Environment Simulation

This directory contains a fully containerized, reproducible lab environment to demonstrate the `libextractor` OLE2 VLA stack overflow vulnerability in a realistic scenario.

## Architecture

The lab uses `docker-compose` to orchestrate two containers:

1. **`target` (libextractor-vulnerable):**
   - Builds `libextractor` from source (simulating an upstream build without `-fstack-clash-protection`).
   - Runs `upload_server.py`, a simulated Document Indexing web service listening on port 8080.
   - Accepts uploaded `.doc` files and processes them via `libextractor` to extract metadata.

2. **`attacker` (libextractor-attacker):**
   - An ephemeral Python container that simulates a malicious actor.
   - Uses `poc/gen_payload.py` to generate a malicious 3.9MB `.doc` file.
   - Sends the file to the `target` via an HTTP POST request (`curl`).
   - The payload triggers the vulnerability on the target, resulting in arbitrary code execution.

## Usage

**Note:** The docker-compose commands must be run from the **root of the repository**, not from inside this directory!

### 1. Start the Lab
To build the vulnerable target and launch the automated attack, run:
```bash
docker compose -f lab-setup/docker-compose.yml up --build
```

### 2. What Happens?
1. The `target` container compiles `libextractor` and starts the web service.
2. The `attacker` container boots up, generates `exploit.doc`, and uploads it.
3. The `target` server crashes while parsing the file, but because the attacker controlled the execution flow, the payload executes.
4. The payload writes a proof-of-concept file to `/tmp/pwned` inside the `target` container.

### 3. Verify the RCE
Once the `attacker` container finishes its automated script, you can verify that the code execution was successful by checking for the `/tmp/pwned` file on the target:
```bash
docker exec libextractor-vulnerable cat /tmp/pwned
```
*(If successful, this will output the results of commands like `id` and `uname -a` executed by the payload).*

### 4. Cleanup
To stop the containers and clean up the environment:
```bash
docker compose -f lab-setup/docker-compose.yml down
```
