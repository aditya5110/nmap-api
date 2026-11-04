package db

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"nmap-api/internal/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func OpenDB(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	pgCfg, err := pgxConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("parse postgres config: %w", err)
	}

	db := stdlib.OpenDB(*pgCfg)
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return db, nil
}

func pgxConfig(cfg config.Config) (*pgx.ConnConfig, error) {
	dsn := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.DBUser, cfg.DBPassword),
		Host:   net.JoinHostPort(cfg.DBHost, strconv.Itoa(cfg.DBPort)),
		Path:   cfg.DBName,
		RawQuery: url.Values{
			"sslmode": {cfg.DBSSLMode},
		}.Encode(),
	}

	return pgx.ParseConfig(dsn.String())
}
