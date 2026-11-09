# Nmap API -- Testing Guide

This guide explains how to start an Ubuntu VM, obtain its IP address,
reset the PostgreSQL database, rebuild the API, and test the scan, scan
history, and port changes functionality.

## 1. Start the Ubuntu Virtual Machine

1.  Open your virtualization platform (VirtualBox, VMware, UTM, cloud
    console, etc.).
2.  Select your Ubuntu virtual machine.
3.  Click **Start** or **Power On**.
4.  Wait for Ubuntu to boot.
5.  Log in to the Ubuntu VM.

Make sure the VM is connected to a network that allows your API
container to reach it.

## 2. Find the Ubuntu VM's IP Address

Open a terminal inside Ubuntu and run:

``` bash
hostname -I
```

This displays the IP addresses assigned to the VM.

Alternatively, use:

``` bash
ip -4 addr show
```

Identify the IPv4 address associated with the active network interface.

For example:

``` text
192.168.x.x
```

Use the actual IP address of your VM wherever `<UBUNTU_MACHINE_IP>`
appears in the commands and Postman URLs below.

**Important:** The VM must be reachable from the machine or Docker
container running the Nmap API. If the API runs inside Docker, verify
connectivity from the API container as well.

## 3. Clear All Existing Scan Data (Fresh Start)

To delete all existing scan data from PostgreSQL and reset the
auto-incrementing IDs, run this command from the project directory:

``` bash
docker compose exec postgres psql -U appuser -d nmapdb -c "TRUNCATE TABLE scan_ports, scan_results, scan_jobs, scan_requests RESTART IDENTITY CASCADE;"
```

This clears the data from all four tables while keeping their structure
intact.

## 4. Rebuild and Restart the API

Whenever you make changes to the API code, rebuild and restart the API
service:

``` bash
docker compose up --build -d api
```

Verify that the API container is running:

``` bash
docker compose ps api
```

Check that the container is up and running.

## 5. Start an HTTP Server on Ubuntu

Open a terminal inside the Ubuntu VM and start a simple HTTP server on
port `8080`:

``` bash
python3 -m http.server 8080 --bind 0.0.0.0
```

Keep this terminal running while performing the first scan.

The server listens on all network interfaces, allowing connections from
other machines that can reach the VM.

## 6. Submit the First Scan Request

Open Postman and send the following request.

**Method:** `POST`

**URL:**

``` text
http://localhost:8080/api/v1/scans
```

**Body:** Select `raw` → `JSON` and provide:

``` json
{
  "targets": ["<UBUNTU_MACHINE_IP>"],
  "timeout_seconds": 60
}
```

Replace `<UBUNTU_MACHINE_IP>` with the actual IP address obtained in
Step 2.

Click **Send** to submit the scan request.

## 7. Verify Scan History

After the scan completes, send the following GET request in Postman.

**Method:** `GET`

**URL:**

``` text
http://localhost:8080/api/v1/targets/<UBUNTU_MACHINE_IP>/scans?limit=5
```

Verify that the scan appears in the response and that port `8080` is
reported as **open**.

## 8. Stop the HTTP Server on Ubuntu

Go back to the Ubuntu terminal where the HTTP server is running and
press:

``` text
Ctrl + C
```

This stops the HTTP server.

## 9. Verify That Port 8080 Is No Longer Listening

Run the following command on Ubuntu:

``` bash
sudo ss -lntp | grep 8080
```

Verify that there is no output, indicating that nothing is listening on
port `8080`.

## 10. Submit the Second Scan Request

Return to Postman and submit the same POST request again.

**Method:** `POST`

**URL:**

``` text
http://localhost:8080/api/v1/scans
```

**Body:**

``` json
{
  "targets": ["<UBUNTU_MACHINE_IP>"],
  "timeout_seconds": 60
}
```

This creates another scan after the HTTP server has been stopped.

## 11. Verify the Second Scan

Send the same GET request again.

**Method:** `GET`

**URL:**

``` text
http://localhost:8080/api/v1/targets/<UBUNTU_MACHINE_IP>/scans?limit=5
```

Check the scan history and compare the results of the two scans.

## 12. Verify Port Changes Between Scans

Finally, send the following GET request in Postman.

**Method:** `GET`

**URL:**

``` text
http://localhost:8080/api/v1/targets/<UBUNTU_MACHINE_IP>/changes
```

Verify the changes between the two scans.

In particular, check whether port `8080` has changed from **open** in
the first scan to **closed** or **filtered** in the second scan.

------------------------------------------------------------------------

## Expected Test Flow

1. **Start Ubuntu VM** — The VM boots successfully.
2. **Obtain VM IP address** — Identify the VM's IP address.
3. **Clear PostgreSQL data** — The database starts with fresh scan records.
4. **Rebuild API** — The latest API code is running.
5. **Start Ubuntu HTTP server** — Port `8080` is listening.
6. **Submit first scan** — The first scan request is created.
7. **Check scan history** — Port `8080` should be reported as open.
8. **Stop HTTP server** — The HTTP server stops.
9. **Check port 8080** — Nothing should be listening on port `8080`.
10. **Submit second scan** — The second scan request is created.
11. **Check scan history** — Both scans should appear in the history.
12. **Check changes endpoint** — Port state changes between the two scans are reported.

## Important Notes

-   The API must be running before submitting requests through Postman.
-   The Ubuntu VM must remain powered on during both scans.
-   Use the same VM IP address for both scans so the API can compare the
    results for the same target.
-   The API container must be able to reach the Ubuntu VM over the
    network.
-   The second scan may report port `8080` as **closed** or
    **filtered**, depending on network conditions and how Nmap can reach
    the target.
-   A **filtered** result does not necessarily mean the port is closed.
    It means Nmap cannot determine whether the port is open or closed
    because network filtering may be interfering with its probes or
    responses.
-   The database reset is optional. Perform it only when you want to
    start testing with a clean scan history.
