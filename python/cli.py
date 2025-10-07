#!/usr/bin/env python3
import argparse
import json
import grpc

import watchdog_pb2 as pb
import watchdog_pb2_grpc as pb_grpc


def print_json(msg):
    # quick-and-dirty protobuf -> dict (using json_format would be nicer, but let's keep deps minimal)
    try:
        # if google.protobuf is available, use it for nicer output
        from google.protobuf.json_format import MessageToDict
        print(json.dumps(MessageToDict(msg, preserving_proto_field_name=True), indent=2))
    except Exception:
        # fallback: repr
        print(msg)


def main():
    ap = argparse.ArgumentParser(description="Simple gRPC client for artisan.watchdog over a Unix socket")
    ap.add_argument("--socket", "-s", required=True, help="Path to the Unix socket, e.g. /tmp/watchdog.sock")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("system-info")
    sub.add_parser("list-apps")
    g = sub.add_parser("get-app"); g.add_argument("name")
    sub.add_parser("list-builds")
    sub.add_parser("list-verifications")

    # simple command executor
    c = sub.add_parser("exec")
    c.add_argument("which", choices=["start", "stop", "reload", "rebuild", "status", "info", "set", "get"])
    c.add_argument("--application", "-a", default="")
    c.add_argument("--field", choices=[
        "GET_CONFIG_FIELD_BUILD_COMMAND",
        "GET_CONFIG_FIELD_RUN_COMMAND",
        "GET_CONFIG_FIELD_DEPENDENCIES_COMMAND",
        "GET_CONFIG_FIELD_LOG_LEVEL",
        "GET_CONFIG_FIELD_MEMORY_CAP",
        "GET_CONFIG_FIELD_CPU_CAP",
        "GET_CONFIG_FIELD_MONITOR_DIRECTORY",
        "GET_CONFIG_FIELD_WORKING_DIRECTORY",
        "GET_CONFIG_FIELD_CHANGES_NEEDED",
        "GET_CONFIG_FIELD_DIR_SCAN_INTERVAL",
    ])
    # One of these for SetConfigValue (only one will be used if provided)
    c.add_argument("--build_command")
    c.add_argument("--run_command")
    c.add_argument("--dependencies_command")
    c.add_argument("--log_level")
    c.add_argument("--memory_cap", type=int)
    c.add_argument("--cpu_cap", type=int)
    c.add_argument("--monitor_directory")
    c.add_argument("--working_directory")
    c.add_argument("--changes_needed", type=int)
    c.add_argument("--dir_scan_interval", type=int)

    args = ap.parse_args()

    # Connect over a Unix domain socket
    channel = grpc.insecure_channel(f"unix://{args.socket}")
    stub = pb_grpc.WatchdogStub(channel)

    if args.cmd == "system-info":
        resp = stub.GetSystemInfo(pb.Empty())
        print_json(resp)
        return

    if args.cmd == "list-apps":
        resp = stub.ListApplications(pb.Empty())
        print_json(resp)
        return

    if args.cmd == "get-app":
        resp = stub.GetApplication(pb.ApplicationStatusRequest(name=args.name))
        print_json(resp)
        return

    if args.cmd == "list-builds":
        resp = stub.ListBuilds(pb.Empty())
        print_json(resp)
        return

    if args.cmd == "list-verifications":
        resp = stub.ListVerifications(pb.Empty())
        print_json(resp)
        return

    # ExecuteCommand helper
    if args.cmd == "exec":
        req = None
        which = args.which

        if which == "start":
            req = pb.CommandRequest(start=pb.StartCommand(application=args.application))
        elif which == "stop":
            req = pb.CommandRequest(stop=pb.StopCommand(application=args.application))
        elif which == "reload":
            req = pb.CommandRequest(reload=pb.ReloadCommand(application=args.application))
        elif which == "rebuild":
            req = pb.CommandRequest(rebuild=pb.RebuildCommand(application=args.application))
        elif which == "status":
            req = pb.CommandRequest(status=pb.StatusCommand(application=args.application))
        elif which == "info":
            req = pb.CommandRequest(info=pb.InfoCommand())
        elif which == "set":
            # Build SetConfigValue from whichever one flag was provided
            v = pb.SetConfigValue()
            if args.build_command is not None: v.build_command = args.build_command
            if args.run_command is not None: v.run_command = args.run_command
            if args.dependencies_command is not None: v.dependencies_command = args.dependencies_command
            if args.log_level is not None: v.log_level = args.log_level
            if args.memory_cap is not None: v.memory_cap = args.memory_cap
            if args.cpu_cap is not None: v.cpu_cap = args.cpu_cap
            if args.monitor_directory is not None: v.monitor_directory = args.monitor_directory
            if args.working_directory is not None: v.working_directory = args.working_directory
            if args.changes_needed is not None: v.changes_needed = args.changes_needed
            if args.dir_scan_interval is not None: v.dir_scan_interval = args.dir_scan_interval

            req = pb.CommandRequest(set=pb.SetCommand(application=args.application, value=v))
        elif which == "get":
            field = getattr(pb, args.field) if args.field and hasattr(pb, args.field) else pb.GET_CONFIG_FIELD_UNSPECIFIED
            req = pb.CommandRequest(get=pb.GetCommand(application=args.application, field=field))

        resp = stub.ExecuteCommand(req)
        print_json(resp)
        return


if __name__ == "__main__":
    main()
