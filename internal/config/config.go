package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	APIHost string
	APIPort int

	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	WorkerCount           int
	MaxBatchSize          int
	DefaultTimeoutSeconds int
	AppEnvironment        string
}

func Load() (Config, error) {
	cfg := Config{
		APIHost:               getEnv("API_HOST", "0.0.0.0"),
		APIPort:               8080,
		DBHost:                "",
		DBPort:                5432,
		DBUser:                "",
		DBPassword:            "",
		DBName:                "",
		DBSSLMode:             getEnv("DB_SSLMODE", "disable"),
		WorkerCount:           4,
		MaxBatchSize:          20,
		DefaultTimeoutSeconds: 120,
		AppEnvironment:        getEnv("APP_ENV", "development"),
	}

	var err error
	cfg.APIPort, err = getEnvInt("API_PORT", 8080)
	if err != nil {
		return Config{}, fmt.Errorf("invalid API_PORT: %w", err)
	}
	if cfg.APIPort <= 0 {
		return Config{}, errors.New("API_PORT must be greater than 0")
	}

	cfg.DBHost = getRequiredEnv("DB_HOST")
	cfg.DBPort, err = getEnvInt("DB_PORT", 5432)
	if err != nil {
		return Config{}, fmt.Errorf("invalid DB_PORT: %w", err)
	}
	if cfg.DBPort <= 0 {
		return Config{}, errors.New("DB_PORT must be greater than 0")
	}
	cfg.DBUser = getRequiredEnv("DB_USER")
	cfg.DBPassword = getRequiredEnv("DB_PASSWORD")
	cfg.DBName = getRequiredEnv("DB_NAME")

	cfg.WorkerCount, err = getEnvInt("WORKER_COUNT", 4)
	if err != nil {
		return Config{}, fmt.Errorf("invalid WORKER_COUNT: %w", err)
	}
	if cfg.WorkerCount <= 0 {
		return Config{}, errors.New("WORKER_COUNT must be greater than 0")
	}

	cfg.MaxBatchSize, err = getEnvInt("MAX_BATCH_SIZE", 20)
	if err != nil {
		return Config{}, fmt.Errorf("invalid MAX_BATCH_SIZE: %w", err)
	}
	if cfg.MaxBatchSize <= 0 {
		return Config{}, errors.New("MAX_BATCH_SIZE must be greater than 0")
	}

	cfg.DefaultTimeoutSeconds, err = getEnvInt("DEFAULT_TIMEOUT_SECONDS", 120)
	if err != nil {
		return Config{}, fmt.Errorf("invalid DEFAULT_TIMEOUT_SECONDS: %w", err)
	}
	if cfg.DefaultTimeoutSeconds <= 0 {
		return Config{}, errors.New("DEFAULT_TIMEOUT_SECONDS must be greater than 0")
	}

	return cfg, nil
}

func (c Config) APIAddr() string {
	return fmt.Sprintf("%s:%d", c.APIHost, c.APIPort)
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}

	return parsed, nil
}

func getRequiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("missing required environment variable: %s", key))
	}
	return value
}
