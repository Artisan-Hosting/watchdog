package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	pb "ais/generated/artisan/watchdog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	socketPath := flag.String("socket", "/tmp/artisan_watchdog.sock", "Path to gRPC Unix socket")
	flag.Parse()

	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	}

	command := flag.Arg(0)
	args := flag.Args()[1:]

	conn, err := grpc.Dial(
		"unix://"+*socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.Dial("unix", *socketPath)
		}),
	)
	if err != nil {
		log.Fatalf("failed to connect to socket: %v", err)
	}
	defer conn.Close()

	client := pb.NewWatchdogClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch command {
	case "list":
		listApplications(ctx, client)
	case "info":
		getSystemInfo(ctx, client)
	case "status":
		requireArgs(args, 1, "status <application>")
		getApplicationStatus(ctx, client, args[0])
	case "start", "stop", "reload", "rebuild":
		requireArgs(args, 1, fmt.Sprintf("%s <application>", command))
		executeSimpleCommand(ctx, client, command, args[0])
	case "get":
		requireArgs(args, 2, "get <application> <field>")
		executeGetCommand(ctx, client, args[0], args[1])
	case "set":
		requireArgs(args, 3, "set <application> <field> <value>")
		executeSetCommand(ctx, client, args[0], args[1], args[2])
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: watchdog-cli [command] [args]

Commands:
  list
  info
  status <application>
  start <application>
  stop <application>
  reload <application>
  rebuild <application>
  get <application> <field>
  set <application> <field> <value>

Examples:
  watchdog-cli get myapp log_level
  watchdog-cli set myapp memory_cap 256
  watchdog-cli start myapp
`)
}

func requireArgs(args []string, n int, usage string) {
	if len(args) < n {
		fmt.Printf("Usage: watchdog-cli %s\n", usage)
		os.Exit(1)
	}
}

func listApplications(ctx context.Context, client pb.WatchdogClient) {
	resp, err := client.ListApplications(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("ListApplications: %v", err)
	}
	if len(resp.Applications) == 0 {
		fmt.Println("No applications found.")
		return
	}
	for _, app := range resp.Applications {
		fmt.Printf("%-20s %-10s CPU: %.1f%% Mem: %.1f MB\n",
			app.Name, app.Status, app.CpuUsage, app.MemoryUsage)
	}
}

func getSystemInfo(ctx context.Context, client pb.WatchdogClient) {
	info, err := client.GetSystemInfo(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("GetSystemInfo: %v", err)
	}
	fmt.Printf("Identity: %s\nManager Linked: %v\nSystem Apps Initialized: %v\nIPs: %s\n",
		info.Identity, info.ManagerLinked, info.SystemAppsInitialized, strings.Join(info.IpAddresses, ", "))
}

func getApplicationStatus(ctx context.Context, client pb.WatchdogClient, name string) {
	resp, err := client.GetApplication(ctx, &pb.ApplicationStatusRequest{Name: name})
	if err != nil {
		log.Fatalf("GetApplication: %v", err)
	}
	if !resp.Found {
		fmt.Printf("Application '%s' not found.\n", name)
		return
	}
	app := resp.Status
	fmt.Printf("App: %s\nStatus: %s\nCPU: %.2f%%\nMem: %.2f MB\n", app.Name, app.Status, app.CpuUsage, app.MemoryUsage)
}

func executeSimpleCommand(ctx context.Context, client pb.WatchdogClient, cmd string, app string) {
	var req *pb.CommandRequest
	switch cmd {
	case "start":
		req = &pb.CommandRequest{Payload: &pb.CommandRequest_Start{Start: &pb.StartCommand{Application: app}}}
	case "stop":
		req = &pb.CommandRequest{Payload: &pb.CommandRequest_Stop{Stop: &pb.StopCommand{Application: app}}}
	case "reload":
		req = &pb.CommandRequest{Payload: &pb.CommandRequest_Reload{Reload: &pb.ReloadCommand{Application: app}}}
	case "rebuild":
		req = &pb.CommandRequest{Payload: &pb.CommandRequest_Rebuild{Rebuild: &pb.RebuildCommand{Application: app}}}
	default:
		log.Fatalf("Unsupported command: %s", cmd)
	}

	resp, err := client.ExecuteCommand(ctx, req)
	if err != nil {
		log.Fatalf("ExecuteCommand: %v", err)
	}
	fmt.Printf("[%s] accepted=%v message=%s\n", strings.ToUpper(cmd), resp.Accepted, resp.Message)
}

func executeGetCommand(ctx context.Context, client pb.WatchdogClient, app string, field string) {
	fieldEnum, ok := getFieldEnum(field)
	if !ok {
		fmt.Printf("Unknown field: %s\n", field)
		os.Exit(1)
	}
	req := &pb.CommandRequest{
		Payload: &pb.CommandRequest_Get{
			Get: &pb.GetCommand{
				Application: app,
				Field:       fieldEnum,
			},
		},
	}

	resp, err := client.ExecuteCommand(ctx, req)
	if err != nil {
		log.Fatalf("ExecuteCommand (get): %v", err)
	}
	fmt.Printf("[GET] accepted=%v message=%s\n", resp.Accepted, resp.Message)
}

func executeSetCommand(ctx context.Context, client pb.WatchdogClient, app, field, value string) {
	val, ok := buildSetValue(field, value)
	if !ok {
		fmt.Printf("Unknown or invalid field: %s\n", field)
		os.Exit(1)
	}

	req := &pb.CommandRequest{
		Payload: &pb.CommandRequest_Set{
			Set: &pb.SetCommand{
				Application: app,
				Value:       val,
			},
		},
	}

	resp, err := client.ExecuteCommand(ctx, req)
	if err != nil {
		log.Fatalf("ExecuteCommand (set): %v", err)
	}
	fmt.Printf("[SET] accepted=%v message=%s\n", resp.Accepted, resp.Message)
}

func getFieldEnum(name string) (pb.GetConfigField, bool) {
	switch strings.ToLower(name) {
	case "build_command":
		return pb.GetConfigField_GET_CONFIG_FIELD_BUILD_COMMAND, true
	case "run_command":
		return pb.GetConfigField_GET_CONFIG_FIELD_RUN_COMMAND, true
	case "dependencies_command":
		return pb.GetConfigField_GET_CONFIG_FIELD_DEPENDENCIES_COMMAND, true
	case "log_level":
		return pb.GetConfigField_GET_CONFIG_FIELD_LOG_LEVEL, true
	case "memory_cap":
		return pb.GetConfigField_GET_CONFIG_FIELD_MEMORY_CAP, true
	case "cpu_cap":
		return pb.GetConfigField_GET_CONFIG_FIELD_CPU_CAP, true
	case "monitor_directory":
		return pb.GetConfigField_GET_CONFIG_FIELD_MONITOR_DIRECTORY, true
	case "working_directory":
		return pb.GetConfigField_GET_CONFIG_FIELD_WORKING_DIRECTORY, true
	case "changes_needed":
		return pb.GetConfigField_GET_CONFIG_FIELD_CHANGES_NEEDED, true
	case "dir_scan_interval":
		return pb.GetConfigField_GET_CONFIG_FIELD_DIR_SCAN_INTERVAL, true
	default:
		return pb.GetConfigField_GET_CONFIG_FIELD_UNSPECIFIED, false
	}
}

func buildSetValue(field, value string) (*pb.SetConfigValue, bool) {
	switch strings.ToLower(field) {
	case "build_command":
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_BuildCommand{BuildCommand: value}}, true
	case "run_command":
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_RunCommand{RunCommand: value}}, true
	case "dependencies_command":
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_DependenciesCommand{DependenciesCommand: value}}, true
	case "log_level":
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_LogLevel{LogLevel: value}}, true
	case "memory_cap":
		i, err := strconv.Atoi(value)
		if err != nil {
			return nil, false
		}
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_MemoryCap{MemoryCap: uint32(i)}}, true
	case "cpu_cap":
		i, err := strconv.Atoi(value)
		if err != nil {
			return nil, false
		}
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_CpuCap{CpuCap: uint32(i)}}, true
	case "monitor_directory":
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_MonitorDirectory{MonitorDirectory: value}}, true
	case "working_directory":
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_WorkingDirectory{WorkingDirectory: value}}, true
	case "changes_needed":
		i, err := strconv.Atoi(value)
		if err != nil {
			return nil, false
		}
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_ChangesNeeded{ChangesNeeded: uint32(i)}}, true
	case "dir_scan_interval":
		i, err := strconv.Atoi(value)
		if err != nil {
			return nil, false
		}
		return &pb.SetConfigValue{Value: &pb.SetConfigValue_DirScanInterval{DirScanInterval: uint32(i)}}, true
	default:
		return nil, false
	}
}
