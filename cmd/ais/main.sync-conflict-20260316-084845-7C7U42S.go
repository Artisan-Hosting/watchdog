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

const (
	aisPrefix  = "ais_"
	appManager = "manager"
	appGitmon  = "gitmon"
	appMailler = "mailler"
)

var systemApplications = map[string]struct{}{
	aisPrefix + appManager: {},
	aisPrefix + appGitmon:  {},
	aisPrefix + appMailler: {},
}

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
	case "usage":
		requireArgs(args, 1, "usage <application> [start] [end]")
		start, end := parseWindowArgs(args[1:])
		queryUsage(ctx, conn, args[0], start, end)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: ais [command] [args]

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
  usage <application> [start] [end]

Examples:
  ais get myapp log_level
  ais set myapp memory_cap 256
  ais start myapp
`)
}

func requireArgs(args []string, n int, usage string) {
	if len(args) < n {
		fmt.Printf("Usage: ais %s\n", usage)
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

	systemApps := make([]*pb.ApplicationStatusMessage, 0)
	clientApps := make([]*pb.ApplicationStatusMessage, 0)

	for _, app := range resp.Applications {
		if isSystemApplication(app.Name) {
			systemApps = append(systemApps, app)
			continue
		}
		clientApps = append(clientApps, app)
	}

	if len(systemApps) > 0 {
		fmt.Println("System Applications:")
		for _, app := range systemApps {
			fmt.Printf("  %-20s %-10s CPU: %.2f%% Mem: %.1f MB\n",
				app.Name, app.Status, app.CpuUsage, app.MemoryUsage)
		}
	}

	if len(clientApps) > 0 {
		if len(systemApps) > 0 {
			fmt.Println()
		}
		fmt.Println("Client Applications:")
		for _, app := range clientApps {
			fmt.Printf("  %-20s %-10s CPU: %.2f%% Mem: %.1f MB\n",
				app.Name, app.Status, app.CpuUsage, app.MemoryUsage)
		}
	}
}

func isSystemApplication(name string) bool {
	_, ok := systemApplications[name]
	return ok
}

func getSystemInfo(ctx context.Context, client pb.WatchdogClient) {
	info, err := client.GetSystemInfo(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("GetSystemInfo: %v", err)
	}
	versions, err := client.GetVersionInfo(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("GetVersionInfo: %v", err)
	}
	fmt.Printf(
		"Identity: %s\nManager Linked: %v\nSystem Apps Initialized: %v\nSecurity Tripped: %v\nSecurity Trip Detected At: %d\nSecurity Trip Summary: %s\nWatchdog Version: %s\nArtisan Middleware Version: %s\nIPs: %s\n",
		info.Identity,
		info.ManagerLinked,
		info.SystemAppsInitialized,
		info.SecurityTripped,
		info.SecurityTripDetectedAt,
		info.SecurityTripSummary,
		versions.WatchdogVersion,
		versions.ArtisanMiddlewareVersion,
		strings.Join(info.IpAddresses, ", "),
	)
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
	if app.NetworkUsage != nil {
		fmt.Printf(
			"App: %s\nStatus: %s\nCPU: %.2f%%\nMem: %.2f MB\nNet RX: %d B\nNet TX: %d B\n",
			app.Name,
			app.Status,
			app.CpuUsage,
			app.MemoryUsage,
			app.NetworkUsage.RxBytes,
			app.NetworkUsage.TxBytes,
		)
		return
	}
	fmt.Printf("App: %s\nStatus: %s\nCPU: %.2f%%\nMem: %.2f MB\nNet: unavailable\n", app.Name, app.Status, app.CpuUsage, app.MemoryUsage)
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

func queryUsage(ctx context.Context, conn *grpc.ClientConn, app string, start, end uint64) {
	req := &pb.UsageQueryRequest{
		Application: app,
		Start:       start,
		End:         end,
	}
	resp := &pb.UsageQueryResponse{}
	if err := conn.Invoke(ctx, "/artisan.watchdog.Watchdog/QueryUsage", req, resp); err != nil {
		log.Fatalf("QueryUsage: %v", err)
	}
	if !resp.Found {
		fmt.Printf("No usage data for %s in the requested window.\n", app)
		return
	}
	rxHuman := humanBytes(resp.TotalRx)
	txHuman := humanBytes(resp.TotalTx)
	fmt.Printf(
		"Usage for %s (%d samples)\n  Window: %s -> %s\n  Avg CPU: %.2f%%\n  Avg Mem: %.2f MB\n  Peak Mem: %.2f MB\n  Net RX: %s\n  Net TX: %s\n",
		resp.Application,
		resp.SampleCount,
		formatTimestamp(resp.Start),
		formatTimestamp(resp.End),
		resp.AvgCpu,
		resp.AvgMem,
		resp.PeakMem,
		rxHuman,
		txHuman,
	)
}

func formatTimestamp(ts uint64) string {
	if ts == 0 {
		return "(unset)"
	}
	return time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)
}

func parseWindowArgs(args []string) (uint64, uint64) {
	var start, end uint64
	var err error
	if len(args) >= 1 {
		start, err = parseUintArg(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid start timestamp: %v\n", err)
			os.Exit(1)
		}
	}
	if len(args) >= 2 {
		end, err = parseUintArg(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid end timestamp: %v\n", err)
			os.Exit(1)
		}
	}
	return start, end
}

func parseUintArg(raw string) (uint64, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func humanBytes(value uint64) string {
	const (
		KB = 1024.0
		MB = KB * 1024
		GB = MB * 1024
	)
	val := float64(value)
	switch {
	case val >= GB:
		return fmt.Sprintf("%.2f GB", val/GB)
	case val >= MB:
		return fmt.Sprintf("%.2f MB", val/MB)
	case val >= KB:
		return fmt.Sprintf("%.2f KB", val/KB)
	default:
		return fmt.Sprintf("%d B", value)
	}
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
