"""
数据库初始化脚本 — 创建 shell_protector 数据库及全部表结构
运行: python init_db.py
"""

import os
import pymysql
import bcrypt
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASS = os.environ.get("DB_PASS", "")
DB_NAME = os.environ.get("DB_NAME", "shell_protector")

def get_conn(database=None):
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS,
        database=database, charset="utf8mb4", autocommit=True,
    )

def init():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    print(f"[OK] 数据库 {DB_NAME} 已就绪")

    conn.close()
    conn = get_conn(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS `users` (
        `id`            INT AUTO_INCREMENT PRIMARY KEY,
        `username`      VARCHAR(64)  NOT NULL UNIQUE,
        `password_hash` VARCHAR(256) NOT NULL,
        `role`          VARCHAR(32)  NOT NULL DEFAULT 'admin',
        `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        `last_login`    DATETIME     NULL,
        INDEX idx_username (`username`)
    ) ENGINE=InnoDB
    """)
    print("[OK] 表 users 已就绪")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS `risk_reports` (
        `id`                INT AUTO_INCREMENT PRIMARY KEY,
        `device_fingerprint` VARCHAR(256) DEFAULT NULL,
        `risk_level`        VARCHAR(32)  NOT NULL DEFAULT 'UNKNOWN',
        `risk_score`        INT          NOT NULL DEFAULT 0,
        `max_risk_score`    INT          NOT NULL DEFAULT 0,
        `warning_count`     INT          NOT NULL DEFAULT 0,
        `danger_count`      INT          NOT NULL DEFAULT 0,
        `sdk_version`       VARCHAR(32)  DEFAULT NULL,
        `report_json`       JSON         NOT NULL,
        `created_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_risk_level (`risk_level`),
        INDEX idx_created_at (`created_at`),
        INDEX idx_fingerprint (`device_fingerprint`)
    ) ENGINE=InnoDB
    """)
    print("[OK] 表 risk_reports 已就绪")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS `device_fingerprints` (
        `id`                INT AUTO_INCREMENT PRIMARY KEY,
        `report_id`         INT          NOT NULL,
        `field_name`        VARCHAR(128) NOT NULL,
        `field_value`       TEXT         DEFAULT NULL,
        `source`            VARCHAR(64)  DEFAULT NULL,
        `created_at`        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_report_id (`report_id`),
        INDEX idx_field_name (`field_name`),
        FOREIGN KEY (`report_id`) REFERENCES `risk_reports`(`id`) ON DELETE CASCADE
    ) ENGINE=InnoDB
    """)
    print("[OK] 表 device_fingerprints 已就绪")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS `detection_results` (
        `id`            INT AUTO_INCREMENT PRIMARY KEY,
        `report_id`     INT          NOT NULL,
        `detector_name` VARCHAR(128) NOT NULL,
        `status`        VARCHAR(32)  NOT NULL,
        `risk_level`    VARCHAR(32)  DEFAULT NULL,
        `score`         INT          NOT NULL DEFAULT 0,
        `details`       JSON         DEFAULT NULL,
        `created_at`    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_report_id (`report_id`),
        INDEX idx_detector (`detector_name`),
        FOREIGN KEY (`report_id`) REFERENCES `risk_reports`(`id`) ON DELETE CASCADE
    ) ENGINE=InnoDB
    """)
    print("[OK] 表 detection_results 已就绪")

    # 插入默认 admin 用户（如不存在）
    cur.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cur.fetchone()[0] == 0:
        pw_hash = bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode("utf-8")
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ("admin", pw_hash, "admin"),
        )
        print("[OK] 默认管理员 admin/admin 已创建")
    else:
        print("[OK] 管理员用户已存在，跳过")

    conn.close()
    print("\n数据库初始化完成！")

if __name__ == "__main__":
    init()
