import sys
import runpy
import json

processes = []
network_attempts = []


def audit_hook(event, args):
    if event == "subprocess.Popen":
        try:
            command = args[0]

            if isinstance(command, (list, tuple)):
                process_name = str(command[0])
            else:
                process_name = str(command)

            processes.append(process_name)

        except Exception:
            pass

    if event == "socket.connect":
        try:
            address = args[1]

            if isinstance(address, tuple) and len(address) >= 2:
                host = str(address[0])
                port = str(address[1])

                network_attempts.append(
                    f"{host}:{port}"
                )

        except Exception:
            pass


sys.addaudithook(audit_hook)

script_path = sys.argv[1]

try:
    runpy.run_path(script_path, run_name="__main__")
finally:
    print(
        "__VIBEGUARD_TELEMETRY__"
        + json.dumps({
            "processesSpawned": processes,
            "networkAttempts": network_attempts
        })
    )