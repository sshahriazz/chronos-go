// Command migrate applies database migrations.
//
// Migrations are EMBEDDED in the binary, so the image is self-contained and
// cannot drift from a mounted directory — the same property cmd/apidocs has for
// documentation. That is the main reason this uses Goose rather than Atlas
// (ADR-011).
//
// It connects with the OWNER credentials, not the application role: creating
// tables, policies and grants requires privileges the application must never
// hold (ADR-015).
package main

import (
	"context"
	"database/sql"
	"embed"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

const dir = "migrations"

func main() {
	cmd := flag.String("cmd", "up", "up | down | status | version | up-to | redo")
	arg := flag.String("arg", "", "argument for commands that take one, e.g. a version")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(*cmd, *arg, log); err != nil {
		log.Error("migration failed", "error", err)
		os.Exit(1)
	}
}

func run(cmd, arg string, log *slog.Logger) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is not set")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	goose.SetBaseFS(migrations)
	goose.SetLogger(gooseLogger{log})
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	switch cmd {
	case "up":
		return goose.UpContext(ctx, db, dir)
	case "up-to":
		v, err := parseVersion(arg)
		if err != nil {
			return err
		}
		return goose.UpToContext(ctx, db, dir, v)
	case "down":
		// One step at a time, deliberately: a bulk rollback is almost never
		// what someone means at 3am.
		return goose.DownContext(ctx, db, dir)
	case "redo":
		return goose.RedoContext(ctx, db, dir)
	case "status":
		return goose.StatusContext(ctx, db, dir)
	case "version":
		v, err := goose.GetDBVersionContext(ctx, db)
		if err != nil {
			return err
		}
		log.Info("current schema version", "version", v)
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func parseVersion(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("-arg is required for this command")
	}
	var v int64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("invalid version %q: %w", s, err)
	}
	return v, nil
}

// gooseLogger routes Goose's output through slog so migration output matches
// every other log line in the system.
type gooseLogger struct{ log *slog.Logger }

func (g gooseLogger) Printf(format string, v ...any) {
	g.log.Info(trimNewline(fmt.Sprintf(format, v...)))
}

func (g gooseLogger) Fatalf(format string, v ...any) {
	g.log.Error(trimNewline(fmt.Sprintf(format, v...)))
	os.Exit(1)
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
