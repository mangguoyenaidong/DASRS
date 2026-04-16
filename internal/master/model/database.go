package model

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// InitDB 初始化数据库连接
func InitDB(cfg *Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Master.Database.Username,
		cfg.Master.Database.Password,
		cfg.Master.Database.Host,
		cfg.Master.Database.Port,
		cfg.Master.Database.Name,
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// 显式设置连接字符集为 utf8mb4
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	if _, err := sqlDB.Exec("SET NAMES utf8mb4"); err != nil {
		return nil, fmt.Errorf("failed to set names utf8mb4: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.Master.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Master.Database.MaxIdleConns)

	return db, nil
}
r)
	}

	if _, err := sqlDB.Exec("SET NAMES utf8mb4"); err != nil {
		return nil, fmt.Errorf("failed to set names utf8mb4: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.Master.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Master.Database.MaxIdleConns)

	return db, nil
}
