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

	var db *gorm.DB
	var err error

	// 增加重试逻辑 (最多 10 次，每次间隔 2s)
	// 解决 MySQL 容器启动初期可能无法连接的问题
	for i := 1; i <= 10; i++ {
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
		if err == nil {
			break
		}
		fmt.Printf("[DB-INIT] 正在尝试连接数据库 (%d/10)... %v\n", i, err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect database after 10 retries: %w", err)
	}

	// 获取 sql.DB 进行连接池设置
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// 显式设置连接字符集为 utf8mb4
	if _, err := sqlDB.Exec("SET NAMES utf8mb4"); err != nil {
		return nil, fmt.Errorf("failed to set names utf8mb4: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.Master.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Master.Database.MaxIdleConns)

	return db, nil
}
