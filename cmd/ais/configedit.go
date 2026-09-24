package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pb "ais/generated/artisan/watchdog"

	"github.com/BurntSushi/toml"
)

const configRPCTimeout = 10 * time.Second

var configPromptReader = bufio.NewReader(os.Stdin)

type editableConfig struct {
	kind    pb.ConfigFileKind
	current *pb.GetConfigFileResponse
}

func runSetup(client pb.WatchdogClient, args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: ais setup [application]")
	}

	expected, err := listExpectedApps(client)
	if err != nil {
		return err
	}

	targets := append([]string(nil), expected.Expected...)
	if len(args) == 1 {
		resolved, resolveErr := resolveAppID(args[0], targets)
		if resolveErr != nil {
			return resolveErr
		}
		targets = []string{resolved}
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		fmt.Println("No applications found in git credentials.")
		return nil
	}

	var setupErrors []error
	for _, app := range targets {
		if err := setupApplication(client, app); err != nil {
			fmt.Fprintf(os.Stderr, "setup %s: %v\n", app, err)
			setupErrors = append(setupErrors, fmt.Errorf("%s: %w", app, err))
		}
	}
	return errors.Join(setupErrors...)
}

func setupApplication(client pb.WatchdogClient, app string) error {
	files := make([]editableConfig, 0, 2)
	for _, kind := range allConfigKinds() {
		current, err := getConfigFile(client, app, kind, true)
		if err != nil {
			return fmt.Errorf("get %s: %w", configKindName(kind), err)
		}
		state := "exists"
		if current.Created {
			state = "scaffolded"
		}
		fmt.Printf("[%s] %s: %s (%s)\n", app, configKindName(kind), current.Path, state)
		files = append(files, editableConfig{kind: kind, current: current})
	}

	return editApplicationFiles(client, app, files)
}

func runEdit(client pb.WatchdogClient, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: ais edit <application> [config|overrides]")
	}

	expected, err := listExpectedApps(client)
	if err != nil {
		return err
	}
	app, err := resolveAppID(args[0], expected.Expected)
	if err != nil {
		return err
	}

	kinds := allConfigKinds()
	if len(args) == 2 {
		kind, parseErr := parseConfigKind(args[1])
		if parseErr != nil {
			return parseErr
		}
		kinds = []pb.ConfigFileKind{kind}
	}

	files := make([]editableConfig, 0, len(kinds))
	for _, kind := range kinds {
		current, getErr := getConfigFile(client, app, kind, false)
		if getErr != nil {
			return fmt.Errorf("get %s: %w", configKindName(kind), getErr)
		}
		if !current.Found {
			return fmt.Errorf("%s file missing for %s; run 'ais setup %s' first", configKindName(kind), app, app)
		}
		files = append(files, editableConfig{kind: kind, current: current})
	}

	return editApplicationFiles(client, app, files)
}

func editApplicationFiles(client pb.WatchdogClient, app string, files []editableConfig) (resultErr error) {
	confirmed, err := confirmStopStart(app)
	if err != nil {
		return err
	}
	if !confirmed {
		fmt.Printf("Skipped editing %s.\n", app)
		return nil
	}

	stopResponse, err := executeLifecycleCommand(client, app, false)
	if err != nil {
		return fmt.Errorf("stop %s: %w", app, err)
	}
	stopped := stopResponse.Accepted
	if !stopped {
		if strings.Contains(strings.ToLower(stopResponse.Message), "could not find") {
			fmt.Printf("%s was not running; continuing with the edit.\n", app)
		} else {
			return fmt.Errorf("watchdog rejected stop for %s: %s", app, stopResponse.Message)
		}
	} else {
		fmt.Printf("Stopped %s: %s\n", app, stopResponse.Message)
	}

	completed := false
	defer func() {
		if !stopped {
			return
		}

		restart := completed
		if !completed {
			var promptErr error
			restart, promptErr = promptYesNo(fmt.Sprintf("Editing %s was interrupted. Restart it anyway? [Y/n] ", app), true)
			if promptErr != nil {
				resultErr = errors.Join(resultErr, promptErr)
				return
			}
		}
		if !restart {
			fmt.Printf("%s remains stopped.\n", app)
			return
		}

		response, startErr := executeLifecycleCommand(client, app, true)
		if startErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restart %s: %w", app, startErr))
			return
		}
		if !response.Accepted {
			resultErr = errors.Join(resultErr, fmt.Errorf("watchdog rejected restart for %s: %s", app, response.Message))
			return
		}
		fmt.Printf("Started %s: %s\n", app, response.Message)
	}()

	for _, file := range files {
		if _, err := editAndPush(client, app, file.kind, file.current); err != nil {
			return fmt.Errorf("edit %s: %w", configKindName(file.kind), err)
		}
	}
	completed = true
	return nil
}

func editAndPush(client pb.WatchdogClient, app string, kind pb.ConfigFileKind, current *pb.GetConfigFileResponse) (bool, error) {
	tempDir, err := os.MkdirTemp("", "ais-edit-*")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(tempDir)

	tempPath := filepath.Join(tempDir, filepath.Base(current.Path))
	if err := os.WriteFile(tempPath, []byte(current.Content), 0o600); err != nil {
		return false, err
	}

	for {
		if err := launchEditor(tempPath); err != nil {
			return false, err
		}
		editedBytes, err := os.ReadFile(tempPath)
		if err != nil {
			return false, err
		}
		edited := string(editedBytes)
		if edited == current.Content {
			fmt.Printf("No changes to %s for %s.\n", configKindName(kind), app)
			return false, nil
		}

		if err := validateLocalTOML(edited); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid TOML: %v\n", err)
			editAgain, promptErr := promptEditAgain()
			if promptErr != nil {
				return false, promptErr
			}
			if editAgain {
				continue
			}
			fmt.Printf("Discarded changes to %s for %s.\n", configKindName(kind), app)
			return false, nil
		}

		response, err := setConfigFile(client, app, kind, edited, current.Sha256)
		if err != nil {
			return false, err
		}
		if response.Accepted {
			backup := response.BackupFile
			if backup == "" {
				backup = "none"
			}
			fmt.Printf("Wrote %s for %s (backup: %s).\n", configKindName(kind), app, backup)
			return true, nil
		}

		fmt.Fprintf(os.Stderr, "Watchdog rejected the write: %s\n", response.Message)
		latest, err := getConfigFile(client, app, kind, false)
		if err != nil {
			return false, fmt.Errorf("refresh after rejected write: %w", err)
		}
		if !latest.Found {
			return false, fmt.Errorf("%s disappeared while it was being edited", latest.Path)
		}
		current = latest
		if err := os.WriteFile(tempPath, []byte(current.Content), 0o600); err != nil {
			return false, err
		}
		fmt.Fprintln(os.Stderr, "Reloaded the current server version; edit again to reapply your changes.")
	}
}

func launchEditor(path string) error {
	editor := strings.TrimSpace(os.Getenv("VISUAL"))
	if editor == "" {
		editor = strings.TrimSpace(os.Getenv("EDITOR"))
	}
	if editor == "" {
		editor = "vi"
	}
	parts := strings.Fields(editor)
	if len(parts) == 0 {
		return fmt.Errorf("editor command is empty")
	}

	command := exec.Command(parts[0], append(parts[1:], path)...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("editor %q failed: %w", editor, err)
	}
	return nil
}

func validateLocalTOML(content string) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("config content is empty")
	}
	var decoded map[string]any
	_, err := toml.Decode(content, &decoded)
	return err
}

func listExpectedApps(client pb.WatchdogClient) (*pb.ExpectedAppsList, error) {
	ctx, cancel := context.WithTimeout(context.Background(), configRPCTimeout)
	defer cancel()
	return client.ListExpectedApps(ctx, &pb.Empty{})
}

func getConfigFile(client pb.WatchdogClient, app string, kind pb.ConfigFileKind, create bool) (*pb.GetConfigFileResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), configRPCTimeout)
	defer cancel()
	return client.GetConfigFile(ctx, &pb.GetConfigFileRequest{
		Application:     app,
		Kind:            kind,
		CreateIfMissing: create,
	})
}

func setConfigFile(client pb.WatchdogClient, app string, kind pb.ConfigFileKind, content, sha string) (*pb.SetConfigFileResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), configRPCTimeout)
	defer cancel()
	return client.SetConfigFile(ctx, &pb.SetConfigFileRequest{
		Application:            app,
		Kind:                   kind,
		Content:                content,
		ExpectedPreviousSha256: sha,
	})
}

func executeLifecycleCommand(client pb.WatchdogClient, app string, start bool) (*pb.CommandResponse, error) {
	var request *pb.CommandRequest
	if start {
		request = &pb.CommandRequest{Payload: &pb.CommandRequest_Start{Start: &pb.StartCommand{Application: app}}}
	} else {
		request = &pb.CommandRequest{Payload: &pb.CommandRequest_Stop{Stop: &pb.StopCommand{Application: app}}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), configRPCTimeout)
	defer cancel()
	return client.ExecuteCommand(ctx, request)
}

func resolveAppID(input string, expected []string) (string, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", fmt.Errorf("application is required")
	}

	for _, app := range expected {
		if app == raw {
			return app, nil
		}
	}
	prefixed := raw
	if !strings.HasPrefix(prefixed, aisPrefix) {
		prefixed = aisPrefix + prefixed
	}
	for _, app := range expected {
		if app == prefixed {
			return app, nil
		}
	}

	matches := make([]string, 0)
	for _, app := range expected {
		if strings.HasPrefix(app, prefixed) {
			matches = append(matches, app)
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("application %q was not found in git credentials", input)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("application prefix %q is ambiguous: %s", input, strings.Join(matches, ", "))
	}
}

func parseConfigKind(raw string) (pb.ConfigFileKind, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "config":
		return pb.ConfigFileKind_CONFIG_FILE_KIND_CONFIG, nil
	case "overrides", "override":
		return pb.ConfigFileKind_CONFIG_FILE_KIND_OVERRIDES, nil
	default:
		return pb.ConfigFileKind_CONFIG_FILE_KIND_UNSPECIFIED, fmt.Errorf("unknown config file kind %q; use config or overrides", raw)
	}
}

func configKindName(kind pb.ConfigFileKind) string {
	if kind == pb.ConfigFileKind_CONFIG_FILE_KIND_OVERRIDES {
		return "overrides"
	}
	return "config"
}

func allConfigKinds() []pb.ConfigFileKind {
	return []pb.ConfigFileKind{
		pb.ConfigFileKind_CONFIG_FILE_KIND_CONFIG,
		pb.ConfigFileKind_CONFIG_FILE_KIND_OVERRIDES,
	}
}

func confirmStopStart(app string) (bool, error) {
	return promptYesNo(fmt.Sprintf("Editing config for %s requires stopping it. Stop now? [y/N] ", app), false)
}

func promptEditAgain() (bool, error) {
	fmt.Fprint(os.Stderr, "(e)dit again / (q)uit without saving [e]: ")
	answer, err := configPromptReader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "" || answer == "e" || answer == "edit", nil
}

func promptYesNo(prompt string, defaultYes bool) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	answer, err := configPromptReader.ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "" {
		return defaultYes, nil
	}
	if answer == "y" || answer == "yes" {
		return true, nil
	}
	if answer == "n" || answer == "no" {
		return false, nil
	}
	return defaultYes, nil
}
