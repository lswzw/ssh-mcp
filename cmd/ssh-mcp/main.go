package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"ssh-mcp/internal/app"
	"ssh-mcp/internal/hardening"
)

var version = "dev"

var ErrManageRequiresTTY = errors.New("ssh-mcp manage requires an interactive terminal")

type startupMode uint8

const (
	startupServer startupMode = iota
	startupManage
	startupTUI
	startupDaemon
	startupStatus
	startupStop
)

func main() {
	if err := hardening.DisableCoreDumps(); err != nil {
		log.Printf("ssh-mcp stopped: %v", err)
		os.Exit(2)
	}
	mode, err := selectStartupMode(os.Args[1:], isInteractiveTerminal())
	if err != nil {
		log.Printf("ssh-mcp stopped: %v", err)
		os.Exit(2)
	}
	switch mode {
	case startupTUI:
		err = runTUI(os.Args[2:])
	case startupManage:
		err = app.RunManage(context.Background())
	case startupDaemon:
		ctx, stop := daemonSignalContext(context.Background())
		defer stop()
		err = app.RunDaemon(ctx)
	case startupStatus:
		var status app.DaemonStatus
		status, err = app.Status(context.Background())
		if err == nil {
			printStatus(status)
		}
	case startupStop:
		force := len(os.Args) == 3 && os.Args[2] == "--force"
		if force && (!isInteractiveTerminal() || !confirmForceStop()) {
			err = errors.New("ssh-mcp stop --force requires two interactive confirmations")
		} else {
			err = app.Stop(context.Background(), force)
		}
	default:
		err = app.Run(context.Background(), version)
	}
	if err != nil {
		if errors.Is(err, app.ErrAlreadyRunning) {
			log.Printf("ssh-mcp 已在运行，请先退出当前 manage 会话或 MCP 客户端会话后重试")
		} else {
			log.Printf("ssh-mcp stopped: %v", err)
		}
		os.Exit(1)
	}
}

func selectStartupMode(arguments []string, interactive bool) (startupMode, error) {
	if len(arguments) == 0 {
		if interactive {
			return startupManage, nil
		}
		return startupServer, nil
	}
	switch arguments[0] {
	case "serve":
		return startupServer, nil
	case "manage":
		if !interactive {
			return 0, ErrManageRequiresTTY
		}
		return startupManage, nil
	case "tui":
		return startupTUI, nil
	case "daemon":
		return startupDaemon, nil
	case "status":
		if len(arguments) != 1 {
			return 0, fmt.Errorf("ssh-mcp status does not accept arguments")
		}
		return startupStatus, nil
	case "stop":
		if len(arguments) > 2 || (len(arguments) == 2 && arguments[1] != "--force") {
			return 0, fmt.Errorf("usage: ssh-mcp stop [--force]")
		}
		return startupStop, nil
	default:
		return 0, fmt.Errorf("unknown ssh-mcp mode %q", arguments[0])
	}
}

func printStatus(status app.DaemonStatus) {
	if !status.Running {
		fmt.Println("ssh-mcp daemon: stopped")
		return
	}
	lockState := "locked"
	if status.Control.Unlocked {
		lockState = "unlocked"
	}
	fmt.Printf("ssh-mcp daemon: running (%s), bridge sessions: %d\n", lockState, status.ActiveBridgeSessions)
}

func confirmForceStop() bool {
	reader := bufio.NewReader(os.Stdin)
	for attempt := 0; attempt < 2; attempt++ {
		fmt.Fprint(os.Stderr, "停止会中断所有 ssh-mcp 请求，输入 yes 确认: ")
		answer, err := reader.ReadString('\n')
		if err != nil || !isForceStopConfirmation(answer) {
			return false
		}
	}
	return true
}

func isForceStopConfirmation(answer string) bool {
	return strings.TrimSuffix(strings.TrimSuffix(answer, "\n"), "\r") == "yes"
}

func isInteractiveTerminal() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func runTUI(arguments []string) error {
	flags := flag.NewFlagSet("ssh-mcp tui", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	socketPath := flags.String("socket", "", "")
	token := flags.String("token", "", "")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	return app.RunTUI(context.Background(), *socketPath, *token)
}
