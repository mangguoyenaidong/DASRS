package model

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitDB initializes the primary MySQL connection with retries and explicit ping checks.
func InitDB(cfg *Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=5s&readTimeout=10s&writeTimeout=10s&allowNativePasswords=true",
		cfg.Master.Database.Username,
		cfg.Master.Database.Password,
		cfg.Master.Database.Host,
		cfg.Master.Database.Port,
		cfg.Master.Database.Name,
	)

	maskedDSN := fmt.Sprintf(
		"%s:***@tcp(%s:%d)/%s",
		cfg.Master.Database.Username,
		cfg.Master.Database.Host,
		cfg.Master.Database.Port,
		cfg.Master.Database.Name,
	)

	var lastErr error

	for i := 1; i <= 10; i++ {
		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
		if err != nil {
			lastErr = err
			fmt.Printf("[DB-INIT] gorm.Open failed (%d/10) dsn=%s err=%v\n", i, maskedDSN, err)
			time.Sleep(2 * time.Second)
			continue
		}

		sqlDB, err := db.DB()
		if err != nil {
			lastErr = err
			fmt.Printf("[DB-INIT] db.DB failed (%d/10) dsn=%s err=%v\n", i, maskedDSN, err)
			time.Sleep(2 * time.Second)
			continue
		}

		if err := sqlDB.Ping(); err != nil {
			lastErr = err
			fmt.Printf("[DB-INIT] ping failed (%d/10) dsn=%s err=%v\n", i, maskedDSN, err)
			time.Sleep(2 * time.Second)
			continue
		}

		if _, err := sqlDB.Exec("SET NAMES utf8mb4"); err != nil {
			lastErr = err
			fmt.Printf("[DB-INIT] SET NAMES failed (%d/10) dsn=%s err=%v\n", i, maskedDSN, err)
			time.Sleep(2 * time.Second)
			continue
		}

		sqlDB.SetMaxOpenConns(cfg.Master.Database.MaxOpenConns)
		sqlDB.SetMaxIdleConns(cfg.Master.Database.MaxIdleConns)

		fmt.Printf("[DB-INIT] database connected successfully dsn=%s\n", maskedDSN)
		return db, nil
	}

	return nil, fmt.Errorf("failed to connect database after 10 retries: %w", lastErr)
}
